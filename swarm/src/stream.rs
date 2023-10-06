use futures::{AsyncRead, AsyncWrite};
use libp2p_core::muxing::SubstreamBox;
use libp2p_core::Negotiated;
use std::{
    io::{IoSlice, IoSliceMut},
    pin::Pin,
    sync::{Arc, Weak},
    task::{Context, Poll},
};

#[derive(Debug)]
pub struct Stream {
    stream: Negotiated<SubstreamBox>,
    counter: StreamCounter,
}

#[derive(Debug)]
enum StreamCounter {
    Arc(Arc<()>),
    Weak(Weak<()>),
}

impl Stream {
    pub(crate) fn new(stream: Negotiated<SubstreamBox>, counter: Arc<()>) -> Self {
        let counter = StreamCounter::Arc(counter);
        Self { stream, counter }
    }

    /// downgrade the Arc<()> to a Weak<()> which automatically
    /// reduces the strong_count in Connection's stream_counter
    pub fn no_keep_alive(&mut self) {
        if let StreamCounter::Arc(arc_counter) = &self.counter {
            self.counter = StreamCounter::Weak(Arc::downgrade(arc_counter));
        }
    }
}

impl AsyncRead for Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().stream).poll_read(cx, buf)
    }

    fn poll_read_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().stream).poll_read_vectored(cx, bufs)
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().stream).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().stream).poll_write_vectored(cx, bufs)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_close(cx)
    }
}
