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
    collections::{HashMap, HashSet},
    fmt,
    future::Future,
    io::{self, ErrorKind, IoSliceMut},
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};

use futures::{channel::mpsc, prelude::*, ready};
use stun::{
    attributes::ATTR_USERNAME,
    message::{Message as STUNMessage, is_message as is_stun_message},
};
use tokio::{io::ReadBuf, net::UdpSocket};
use webrtc::runtime::{
    AsyncInterval, AsyncTcpListener, AsyncTcpStream, AsyncUdpSocket, JoinHandle, RecvMeta, Runtime,
    Transmit,
};

use crate::tokio::req_res_chan;

const RECEIVE_MTU: usize = 64 * 1024;
const RECEIVE_QUEUE_CAPACITY: usize = 64;
const SEND_QUEUE_CAPACITY: usize = 64;

/// A previously unseen address of a remote which has sent us an ICE binding request.
#[derive(Debug)]
pub(crate) struct NewAddr {
    pub(crate) addr: SocketAddr,
    pub(crate) ufrag: String,
}

/// An event emitted by [`UDPMuxNewAddr`] when it is polled.
#[derive(Debug)]
pub(crate) enum UDPMuxEvent {
    Error(io::Error),
    NewAddr(NewAddr),
}

#[derive(Debug)]
struct Datagram {
    data: Vec<u8>,
    remote_addr: SocketAddr,
}

#[derive(Debug)]
struct Route {
    incoming: mpsc::Sender<Datagram>,
    remote_addrs: HashSet<SocketAddr>,
}

/// Demultiplexes one listening UDP socket into one socket-like handle per ICE ufrag.
pub(crate) struct UDPMuxNewAddr {
    udp_sock: UdpSocket,
    listen_addr: SocketAddr,
    conns: HashMap<String, Route>,
    address_map: HashMap<SocketAddr, String>,
    new_addrs: HashSet<SocketAddr>,
    send_buffer: Option<(Vec<u8>, SocketAddr)>,
    send_command: mpsc::Receiver<(Vec<u8>, SocketAddr)>,
    get_conn_command: req_res_chan::Receiver<String, io::Result<Arc<MuxConnection>>>,
    udp_mux_handle: Arc<UdpMuxHandle>,
}

impl UDPMuxNewAddr {
    pub(crate) fn listen_on(addr: SocketAddr) -> io::Result<Self> {
        let std_sock = std::net::UdpSocket::bind(addr)?;
        std_sock.set_nonblocking(true)?;

        let udp_sock = UdpSocket::from_std(std_sock)?;
        let listen_addr = udp_sock.local_addr()?;
        let (get_conn_sender, get_conn_command) = req_res_chan::new(1);
        let (send_sender, send_command) = mpsc::channel(SEND_QUEUE_CAPACITY);
        let udp_mux_handle = Arc::new(UdpMuxHandle {
            get_conn_sender,
            send_sender: Arc::new(Mutex::new(send_sender)),
        });

        Ok(Self {
            udp_sock,
            listen_addr,
            conns: HashMap::new(),
            address_map: HashMap::new(),
            new_addrs: HashSet::new(),
            send_buffer: None,
            send_command,
            get_conn_command,
            udp_mux_handle,
        })
    }

    pub(crate) fn listen_addr(&self) -> SocketAddr {
        self.listen_addr
    }

    pub(crate) fn udp_mux_handle(&self) -> Arc<UdpMuxHandle> {
        Arc::clone(&self.udp_mux_handle)
    }

    pub(crate) fn poll(&mut self, cx: &mut Context<'_>) -> Poll<UDPMuxEvent> {
        let mut recv_buf = [0u8; RECEIVE_MTU];

        loop {
            self.remove_closed_connections();

            if let Some((buf, target)) = self.send_buffer.take() {
                match self.udp_sock.poll_send_to(cx, &buf, target) {
                    Poll::Ready(Ok(_)) => continue,
                    Poll::Ready(Err(err)) => return Poll::Ready(UDPMuxEvent::Error(err)),
                    Poll::Pending => self.send_buffer = Some((buf, target)),
                }
            } else if let Poll::Ready(Some((buf, target))) = self.send_command.poll_next_unpin(cx) {
                self.send_buffer = Some((buf, target));
                continue;
            }

            if let Poll::Ready(Some((ufrag, response))) = self.get_conn_command.poll_next_unpin(cx)
            {
                let result = if self.conns.contains_key(&ufrag) {
                    Err(io::Error::new(
                        ErrorKind::AlreadyExists,
                        format!("UDP mux connection for ufrag {ufrag} already exists"),
                    ))
                } else {
                    let (incoming, incoming_rx) = mpsc::channel(RECEIVE_QUEUE_CAPACITY);
                    let conn = Arc::new(MuxConnection {
                        ufrag: ufrag.clone(),
                        incoming: Mutex::new(incoming_rx),
                        send_sender: Arc::clone(&self.udp_mux_handle.send_sender),
                    });
                    self.conns.insert(
                        ufrag,
                        Route {
                            incoming,
                            remote_addrs: HashSet::new(),
                        },
                    );
                    Ok(conn)
                };
                let _ = response.send(result);
                continue;
            }

            let mut read = ReadBuf::new(&mut recv_buf);
            match self.udp_sock.poll_recv_from(cx, &mut read) {
                Poll::Ready(Ok(remote_addr)) => {
                    let packet = read.filled();
                    let route = self.route_for_packet(packet, remote_addr);

                    if let Some(ufrag) = route {
                        self.new_addrs.remove(&remote_addr);
                        let Some(route) = self.conns.get_mut(&ufrag) else {
                            continue;
                        };
                        route.remote_addrs.insert(remote_addr);
                        self.address_map.insert(remote_addr, ufrag.clone());
                        if let Err(err) = route.incoming.try_send(Datagram {
                            data: packet.to_vec(),
                            remote_addr,
                        }) {
                            tracing::debug!(
                                address=%remote_addr,
                                %ufrag,
                                "Dropping UDP datagram: receive queue unavailable: {err}",
                            );
                        }
                        continue;
                    }

                    if !self.new_addrs.contains(&remote_addr) {
                        match ufrag_from_stun_message(packet, false) {
                            Ok(ufrag) => {
                                self.new_addrs.insert(remote_addr);
                                return Poll::Ready(UDPMuxEvent::NewAddr(NewAddr {
                                    addr: remote_addr,
                                    ufrag,
                                }));
                            }
                            Err(err) => tracing::debug!(
                                address=%remote_addr,
                                "Unknown address or invalid STUN packet: {err}",
                            ),
                        }
                    }
                    continue;
                }
                Poll::Ready(Err(err)) if err.kind() == ErrorKind::TimedOut => continue,
                Poll::Ready(Err(err)) if err.kind() == ErrorKind::ConnectionReset => {
                    tracing::debug!("Connection reset by remote client: {err}");
                    continue;
                }
                Poll::Ready(Err(err)) => return Poll::Ready(UDPMuxEvent::Error(err)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }

    fn route_for_packet(&self, packet: &[u8], remote_addr: SocketAddr) -> Option<String> {
        if let Some(ufrag) = self.address_map.get(&remote_addr) {
            return Some(ufrag.clone());
        }
        if !is_stun_message(packet) {
            return None;
        }

        let ufrag = ufrag_from_stun_message(packet, true).ok()?;
        let route = self.conns.get(&ufrag)?;
        if route.remote_addrs.is_empty() || route.remote_addrs.contains(&remote_addr) {
            Some(ufrag)
        } else {
            tracing::debug!(
                address=%remote_addr,
                %ufrag,
                "ICE ufrag is already associated with another address",
            );
            None
        }
    }

    fn remove_closed_connections(&mut self) {
        let closed = self
            .conns
            .iter()
            .filter(|(_, route)| route.incoming.is_closed())
            .map(|(ufrag, _)| ufrag.clone())
            .collect::<Vec<_>>();

        for ufrag in closed {
            if let Some(route) = self.conns.remove(&ufrag) {
                for addr in route.remote_addrs {
                    self.address_map.remove(&addr);
                }
            }
        }
    }
}

/// Handle used by connection upgrades to obtain a socket for one ICE ufrag.
pub(crate) struct UdpMuxHandle {
    get_conn_sender: req_res_chan::Sender<String, io::Result<Arc<MuxConnection>>>,
    send_sender: Arc<Mutex<mpsc::Sender<(Vec<u8>, SocketAddr)>>>,
}

impl fmt::Debug for UdpMuxHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UdpMuxHandle").finish_non_exhaustive()
    }
}

impl UdpMuxHandle {
    pub(crate) async fn get_conn(&self, ufrag: &str) -> io::Result<Arc<MuxConnection>> {
        self.get_conn_sender
            .send(ufrag.to_owned())
            .await
            .map_err(|err| io::Error::new(ErrorKind::BrokenPipe, err))?
    }
}

/// A per-ufrag packet queue backed by the listener's shared UDP socket.
pub(crate) struct MuxConnection {
    ufrag: String,
    incoming: Mutex<mpsc::Receiver<Datagram>>,
    send_sender: Arc<Mutex<mpsc::Sender<(Vec<u8>, SocketAddr)>>>,
}

impl fmt::Debug for MuxConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MuxConnection")
            .field("ufrag", &self.ufrag)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
struct MuxedUdpSocket {
    local_addr: SocketAddr,
    conn: Arc<MuxConnection>,
}

impl AsyncUdpSocket for MuxedUdpSocket {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_addr)
    }

    fn poll_send(&self, cx: &mut Context<'_>, transmit: &Transmit<'_>) -> Poll<io::Result<usize>> {
        let mut sender = self
            .conn
            .send_sender
            .lock()
            .map_err(|_| io::Error::other("UDP mux send queue lock poisoned"))?;
        ready!(Pin::new(&mut *sender).poll_ready(cx))
            .map_err(|_| io::Error::new(ErrorKind::BrokenPipe, "UDP mux listener closed"))?;

        let len = transmit.contents.len();
        Pin::new(&mut *sender)
            .start_send((transmit.contents.to_vec(), transmit.destination))
            .map_err(|_| io::Error::new(ErrorKind::BrokenPipe, "UDP mux listener closed"))?;
        Poll::Ready(Ok(len))
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if bufs.is_empty() || meta.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let mut incoming = self
            .conn
            .incoming
            .lock()
            .map_err(|_| io::Error::other("UDP mux receive queue lock poisoned"))?;
        let Some(datagram) = ready!(Pin::new(&mut *incoming).poll_next(cx)) else {
            return Poll::Ready(Err(io::Error::new(
                ErrorKind::BrokenPipe,
                "UDP mux listener closed",
            )));
        };
        if datagram.data.len() > bufs[0].len() {
            return Poll::Ready(Err(io::Error::new(
                ErrorKind::InvalidData,
                "UDP datagram exceeds receive buffer",
            )));
        }

        let len = datagram.data.len();
        bufs[0][..len].copy_from_slice(&datagram.data);
        let mut recv_meta = RecvMeta::default();
        recv_meta.addr = datagram.remote_addr;
        recv_meta.len = len;
        recv_meta.stride = len.max(1);
        recv_meta.dst_ip = Some(self.local_addr.ip());
        meta[0] = recv_meta;
        Poll::Ready(Ok(1))
    }
}

/// Delegates runtime services to webrtc's Tokio runtime while replacing its UDP socket.
#[derive(Debug)]
pub(crate) struct MuxRuntime {
    inner: Arc<dyn Runtime>,
    conn: Arc<MuxConnection>,
}

impl MuxRuntime {
    pub(crate) fn new(conn: Arc<MuxConnection>) -> io::Result<Arc<Self>> {
        let inner = webrtc::runtime::default_runtime()
            .ok_or_else(|| io::Error::other("webrtc Tokio runtime is not enabled"))?;
        Ok(Arc::new(Self { inner, conn }))
    }
}

impl Runtime for MuxRuntime {
    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) -> Box<dyn JoinHandle> {
        self.inner.spawn(future)
    }

    fn spawn_reactor(
        &self,
        reactor_pool_size: usize,
        future: Pin<Box<dyn Future<Output = ()> + Send>>,
    ) -> Box<dyn JoinHandle> {
        self.inner.spawn_reactor(reactor_pool_size, future)
    }

    fn wrap_udp_socket(&self, socket: std::net::UdpSocket) -> io::Result<Arc<dyn AsyncUdpSocket>> {
        let local_addr = socket.local_addr()?;
        drop(socket);
        Ok(Arc::new(MuxedUdpSocket {
            local_addr,
            conn: Arc::clone(&self.conn),
        }))
    }

    fn wrap_tcp_listener(
        &self,
        listener: std::net::TcpListener,
    ) -> io::Result<Arc<dyn AsyncTcpListener>> {
        self.inner.wrap_tcp_listener(listener)
    }

    fn connect_tcp<'a>(
        &'a self,
        remote_addr: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = io::Result<Arc<dyn AsyncTcpStream>>> + Send + 'a>> {
        self.inner.connect_tcp(remote_addr)
    }

    fn resolve_host<'a>(
        &'a self,
        host: &'a str,
    ) -> Pin<Box<dyn Future<Output = io::Result<Vec<SocketAddr>>> + Send + 'a>> {
        self.inner.resolve_host(host)
    }

    fn sleep(&self, duration: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
        self.inner.sleep(duration)
    }

    fn interval(&self, period: Duration) -> Box<dyn AsyncInterval> {
        self.inner.interval(period)
    }

    fn block_on(&self, future: Pin<Box<dyn Future<Output = ()> + '_>>) {
        self.inner.block_on(future)
    }

    fn yield_now(&self) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
        self.inner.yield_now()
    }

    fn name(&self) -> &'static str {
        "tokio-udp-mux"
    }
}

/// Gets one half of the `local:remote` ICE username from a STUN message.
fn ufrag_from_stun_message(buffer: &[u8], local_ufrag: bool) -> io::Result<String> {
    let mut message = STUNMessage::new();
    message
        .unmarshal_binary(buffer)
        .map_err(|err| io::Error::new(ErrorKind::InvalidData, err))?;

    let (attr, found) = message.attributes.get(ATTR_USERNAME);
    if !found {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "no username attribute in STUN message",
        ));
    }

    let username =
        String::from_utf8(attr.value).map_err(|err| io::Error::new(ErrorKind::InvalidData, err))?;
    let (first, second) = username.split_once(':').ok_or_else(|| {
        io::Error::new(
            ErrorKind::InvalidData,
            "ICE username does not contain two ufrags",
        )
    })?;

    Ok(if local_ufrag { first } else { second }.to_owned())
}
