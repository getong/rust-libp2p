// Copyright 2023 Protocol Labs.
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
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::{Bytes, BytesMut};
use futures::{AsyncRead, AsyncWrite, future::BoxFuture, ready};
use webrtc::data_channel::{DataChannel, DataChannelEvent};

/// A substream on top of a WebRTC data channel.
pub struct Stream {
    inner: libp2p_webrtc_utils::Stream<DataChannelIo>,
}

pub(crate) type DropListener = libp2p_webrtc_utils::DropListener<DataChannelIo>;

impl Stream {
    pub(crate) fn new(data_channel: Arc<dyn DataChannel>) -> (Self, DropListener) {
        let (inner, drop_listener) =
            libp2p_webrtc_utils::Stream::new(DataChannelIo::new(data_channel));
        (Self { inner }, drop_listener)
    }
}

impl AsyncRead for Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_close(cx)
    }
}

/// Presents the message-oriented 0.20 data-channel API as a byte stream.
pub(crate) struct DataChannelIo {
    data_channel: Arc<dyn DataChannel>,
    read_fut: Option<BoxFuture<'static, Option<DataChannelEvent>>>,
    write_fut: Option<(usize, BoxFuture<'static, webrtc::error::Result<()>>)>,
    close_fut: Option<BoxFuture<'static, webrtc::error::Result<()>>>,
    read_buffer: Bytes,
    read_closed: bool,
}

impl DataChannelIo {
    fn new(data_channel: Arc<dyn DataChannel>) -> Self {
        Self {
            data_channel,
            read_fut: None,
            write_fut: None,
            close_fut: None,
            read_buffer: Bytes::new(),
            read_closed: false,
        }
    }

    fn poll_pending_write(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<Option<usize>>> {
        let Some((len, fut)) = self.write_fut.as_mut() else {
            return Poll::Ready(Ok(None));
        };
        let len = *len;
        ready!(fut.as_mut().poll(cx)).map_err(io_error)?;
        self.write_fut = None;
        Poll::Ready(Ok(Some(len)))
    }
}

impl Clone for DataChannelIo {
    fn clone(&self) -> Self {
        Self::new(Arc::clone(&self.data_channel))
    }
}

impl Unpin for DataChannelIo {}

impl AsyncRead for DataChannelIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        loop {
            if !self.read_buffer.is_empty() {
                let len = self.read_buffer.len().min(buf.len());
                let data = self.read_buffer.split_to(len);
                buf[..len].copy_from_slice(&data);
                return Poll::Ready(Ok(len));
            }
            if self.read_closed {
                return Poll::Ready(Ok(0));
            }

            let data_channel = Arc::clone(&self.data_channel);
            let fut = self
                .read_fut
                .get_or_insert_with(|| Box::pin(async move { data_channel.poll().await }));
            let event = ready!(fut.as_mut().poll(cx));
            self.read_fut = None;

            match event {
                Some(DataChannelEvent::OnMessage(message)) => {
                    self.read_buffer = message.data.freeze();
                }
                Some(DataChannelEvent::OnClose) | None => self.read_closed = true,
                Some(DataChannelEvent::OnError) => {
                    return Poll::Ready(Err(io::Error::other("WebRTC data channel error")));
                }
                Some(_) => {}
            }
        }
    }
}

impl AsyncWrite for DataChannelIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Poll::Ready(result) = self.poll_pending_write(cx) {
            if let Some(len) = result? {
                return Poll::Ready(Ok(len));
            }
        } else {
            return Poll::Pending;
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let data_channel = Arc::clone(&self.data_channel);
        let data = BytesMut::from(buf);
        let len = data.len();
        self.write_fut = Some((len, Box::pin(async move { data_channel.send(data).await })));
        match self.poll_pending_write(cx) {
            Poll::Ready(Ok(Some(len))) => Poll::Ready(Ok(len)),
            Poll::Ready(Ok(None)) => unreachable!("write future was just installed"),
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.poll_pending_write(cx))?;
        Poll::Ready(Ok(()))
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.as_mut().poll_flush(cx))?;
        let data_channel = Arc::clone(&self.data_channel);
        let fut = self
            .close_fut
            .get_or_insert_with(|| Box::pin(async move { data_channel.close().await }));
        ready!(fut.as_mut().poll(cx)).map_err(io_error)?;
        self.close_fut = None;
        Poll::Ready(Ok(()))
    }
}

fn io_error(error: webrtc::error::Error) -> io::Error {
    io::Error::other(error)
}
