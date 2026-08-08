// Copyright 2022 Parity Technologies (UK) Ltd.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, Waker},
};

use futures::{
    StreamExt, channel::mpsc, future::BoxFuture, lock::Mutex as FutMutex, ready,
    stream::FuturesUnordered,
};
use libp2p_core::muxing::{StreamMuxer, StreamMuxerEvent};
use webrtc::{
    data_channel::{DataChannel, DataChannelEvent},
    peer_connection::{PeerConnection, PeerConnectionEventHandler},
    runtime::Runtime,
};

use crate::tokio::{error::Error, stream, stream::Stream};

const MAX_DATA_CHANNELS_IN_FLIGHT: usize = 10;

/// A WebRTC connection implementing libp2p's stream muxer interface.
pub struct Connection {
    peer_conn: Arc<dyn PeerConnection>,
    incoming_data_channels_rx: mpsc::Receiver<Arc<dyn DataChannel>>,
    outbound_fut: Option<BoxFuture<'static, Result<Arc<dyn DataChannel>, Error>>>,
    close_fut: Option<BoxFuture<'static, Result<(), Error>>>,
    drop_listeners: FuturesUnordered<stream::DropListener>,
    no_drop_listeners_waker: Option<Waker>,
}

impl Unpin for Connection {}

impl Connection {
    pub(crate) fn new(
        peer_conn: Arc<dyn PeerConnection>,
        incoming_data_channels_rx: mpsc::Receiver<Arc<dyn DataChannel>>,
    ) -> Self {
        Self {
            peer_conn,
            incoming_data_channels_rx,
            outbound_fut: None,
            close_fut: None,
            drop_listeners: FuturesUnordered::new(),
            no_drop_listeners_waker: None,
        }
    }
}

impl StreamMuxer for Connection {
    type Substream = Stream;
    type Error = Error;

    fn poll_inbound(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::Substream, Self::Error>> {
        let Some(data_channel) = ready!(self.incoming_data_channels_rx.poll_next_unpin(cx)) else {
            return Poll::Pending;
        };

        tracing::trace!(channel=%data_channel.id(), "Incoming stream");
        let (stream, drop_listener) = Stream::new(data_channel);
        self.drop_listeners.push(drop_listener);
        if let Some(waker) = self.no_drop_listeners_waker.take() {
            waker.wake();
        }
        Poll::Ready(Ok(stream))
    }

    fn poll(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<StreamMuxerEvent, Self::Error>> {
        loop {
            match ready!(self.drop_listeners.poll_next_unpin(cx)) {
                Some(Ok(())) => {}
                Some(Err(err)) => tracing::debug!("a DropListener failed: {err}"),
                None => {
                    self.no_drop_listeners_waker = Some(cx.waker().clone());
                    return Poll::Pending;
                }
            }
        }
    }

    fn poll_outbound(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::Substream, Self::Error>> {
        let peer_conn = Arc::clone(&self.peer_conn);
        let fut = self.outbound_fut.get_or_insert_with(|| {
            Box::pin(async move {
                let data_channel = peer_conn.create_data_channel("", None).await?;
                tracing::trace!(channel=%data_channel.id(), "Opening data channel");
                await_data_channel_open(data_channel).await
            })
        });

        match ready!(fut.as_mut().poll(cx)) {
            Ok(data_channel) => {
                self.outbound_fut = None;
                let (stream, drop_listener) = Stream::new(data_channel);
                self.drop_listeners.push(drop_listener);
                if let Some(waker) = self.no_drop_listeners_waker.take() {
                    waker.wake();
                }
                Poll::Ready(Ok(stream))
            }
            Err(err) => {
                self.outbound_fut = None;
                Poll::Ready(Err(err))
            }
        }
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let peer_conn = Arc::clone(&self.peer_conn);
        let fut = self.close_fut.get_or_insert_with(|| {
            Box::pin(async move {
                peer_conn.close().await?;
                Ok(())
            })
        });

        match ready!(fut.as_mut().poll(cx)) {
            Ok(()) => {
                self.incoming_data_channels_rx.close();
                self.close_fut = None;
                Poll::Ready(Ok(()))
            }
            Err(err) => {
                self.close_fut = None;
                Poll::Ready(Err(err))
            }
        }
    }
}

pub(crate) struct ConnectionHandler {
    incoming_tx: Arc<FutMutex<mpsc::Sender<Arc<dyn DataChannel>>>>,
    runtime: Arc<dyn Runtime>,
}

impl ConnectionHandler {
    pub(crate) fn new(
        runtime: Arc<dyn Runtime>,
    ) -> (Arc<Self>, mpsc::Receiver<Arc<dyn DataChannel>>) {
        let (incoming_tx, incoming_rx) = mpsc::channel(MAX_DATA_CHANNELS_IN_FLIGHT);
        (
            Arc::new(Self {
                incoming_tx: Arc::new(FutMutex::new(incoming_tx)),
                runtime,
            }),
            incoming_rx,
        )
    }
}

#[async_trait::async_trait]
impl PeerConnectionEventHandler for ConnectionHandler {
    async fn on_data_channel(&self, data_channel: Arc<dyn DataChannel>) {
        let incoming_tx = Arc::clone(&self.incoming_tx);
        self.runtime.spawn(Box::pin(async move {
            let channel_id = data_channel.id();
            match await_data_channel_open(data_channel).await {
                Ok(data_channel) => {
                    let mut tx = incoming_tx.lock().await;
                    if let Err(err) = tx.try_send(data_channel.clone()) {
                        tracing::error!(channel=%channel_id, "Can't queue data channel: {err}");
                        if let Err(err) = data_channel.close().await {
                            tracing::error!(channel=%channel_id, "Failed to close data channel: {err}");
                        }
                    }
                }
                Err(err) => tracing::debug!(channel=%channel_id, "Data channel failed to open: {err}"),
            }
        }));
    }
}

#[allow(clippy::result_large_err)]
pub(crate) async fn await_data_channel_open(
    data_channel: Arc<dyn DataChannel>,
) -> Result<Arc<dyn DataChannel>, Error> {
    loop {
        match data_channel.poll().await {
            Some(DataChannelEvent::OnOpen) => return Ok(data_channel),
            Some(DataChannelEvent::OnError) => {
                return Err(Error::Internal("data channel failed to open".into()));
            }
            Some(DataChannelEvent::OnClosing | DataChannelEvent::OnClose) | None => {
                return Err(Error::Internal("data channel closed before opening".into()));
            }
            Some(_) => {}
        }
    }
}
