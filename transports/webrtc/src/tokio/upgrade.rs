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
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use futures::{channel::mpsc, future::Either};
use futures_timer::Delay;
use libp2p_identity as identity;
use libp2p_identity::PeerId;
use libp2p_webrtc_utils::{Fingerprint, noise};
use rtc::{
    ice::{mdns::MulticastDnsMode, network_type::NetworkType},
    peer_connection::transport::{RTCDtlsFingerprint, RTCDtlsRole},
};
use webrtc::{
    data_channel::{DataChannel, RTCDataChannelInit},
    peer_connection::{
        PeerConnection, PeerConnectionBuilder, PeerConnectionEventHandler, RTCConfiguration,
        RTCStatsReportEntry, SettingEngine, StatsSelector,
    },
    runtime::Runtime,
};

use crate::tokio::{
    Connection,
    connection::{ConnectionHandler, await_data_channel_open},
    error::Error,
    sdp,
    sdp::random_ufrag,
    stream::Stream,
    udp_mux::{MuxRuntime, UdpMuxHandle},
};

#[allow(clippy::result_large_err)]
pub(crate) async fn outbound(
    addr: SocketAddr,
    config: RTCConfiguration,
    udp_mux: Arc<UdpMuxHandle>,
    client_fingerprint: Fingerprint,
    server_fingerprint: Fingerprint,
    id_keys: identity::Keypair,
) -> Result<(PeerId, Connection), Error> {
    tracing::debug!(address=%addr, "new outbound connection to address");

    let ufrag = random_ufrag();
    let (peer_connection, incoming_rx) =
        new_peer_connection(addr, config, udp_mux, &ufrag, false).await?;
    let noise_channel = create_noise_data_channel(&peer_connection).await?;

    let offer = peer_connection.create_offer(None).await?;
    tracing::debug!(offer=%offer.sdp, "created SDP offer for outbound connection");
    peer_connection.set_local_description(offer).await?;

    let answer = sdp::answer(addr, server_fingerprint, &ufrag);
    tracing::debug!(?answer, "calculated SDP answer for outbound connection");
    peer_connection.set_remote_description(answer).await?;

    let data_channel = await_noise_data_channel_open(noise_channel).await?;
    let (noise_stream, drop_listener) = Stream::new(data_channel);
    drop(drop_listener);
    let peer_id = noise::outbound(
        id_keys,
        noise_stream,
        server_fingerprint,
        client_fingerprint,
    )
    .await?;

    Ok((peer_id, Connection::new(peer_connection, incoming_rx)))
}

#[allow(clippy::result_large_err)]
pub(crate) async fn inbound(
    addr: SocketAddr,
    config: RTCConfiguration,
    udp_mux: Arc<UdpMuxHandle>,
    server_fingerprint: Fingerprint,
    remote_ufrag: String,
    id_keys: identity::Keypair,
) -> Result<(PeerId, Connection), Error> {
    tracing::debug!(address=%addr, ufrag=%remote_ufrag, "new inbound connection from address");

    let (peer_connection, incoming_rx) =
        new_peer_connection(addr, config, udp_mux, &remote_ufrag, true).await?;
    let noise_channel = create_noise_data_channel(&peer_connection).await?;

    let offer = sdp::offer(addr, &remote_ufrag);
    tracing::debug!(?offer, "calculated SDP offer for inbound connection");
    peer_connection.set_remote_description(offer).await?;

    let answer = peer_connection.create_answer(None).await?;
    tracing::debug!(?answer, "created SDP answer for inbound connection");
    peer_connection.set_local_description(answer).await?;

    let data_channel = await_noise_data_channel_open(noise_channel).await?;
    let client_fingerprint = remote_fingerprint(peer_connection.as_ref()).await?;
    let (noise_stream, drop_listener) = Stream::new(data_channel);
    drop(drop_listener);
    let peer_id = noise::inbound(
        id_keys,
        noise_stream,
        client_fingerprint,
        server_fingerprint,
    )
    .await?;

    Ok((peer_id, Connection::new(peer_connection, incoming_rx)))
}

#[allow(clippy::result_large_err)]
async fn new_peer_connection(
    addr: SocketAddr,
    config: RTCConfiguration,
    udp_mux: Arc<UdpMuxHandle>,
    ufrag: &str,
    inbound: bool,
) -> Result<
    (
        Arc<dyn PeerConnection>,
        mpsc::Receiver<Arc<dyn DataChannel>>,
    ),
    Error,
> {
    let conn = udp_mux.get_conn(ufrag).await?;
    let runtime: Arc<dyn Runtime> = MuxRuntime::new(conn)?;
    let (handler, incoming_rx) = ConnectionHandler::new(Arc::clone(&runtime));
    let handler: Arc<dyn PeerConnectionEventHandler> = handler;

    let mut setting_engine = setting_engine(ufrag, addr);
    if inbound {
        setting_engine.set_lite(true);
        setting_engine.disable_certificate_fingerprint_verification(true);
        setting_engine.set_answering_dtls_role(RTCDtlsRole::Server)?;
    }

    // The runtime discards this temporary socket and substitutes the per-ufrag mux socket.
    let bind_addr = match addr {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };
    let peer_connection = PeerConnectionBuilder::<SocketAddr>::new()
        .with_configuration(config)
        .with_setting_engine(setting_engine)
        .with_runtime(runtime)
        .with_handler(handler)
        .with_udp_addrs(vec![bind_addr])
        .build()
        .await?;

    Ok((Arc::new(peer_connection), incoming_rx))
}

fn setting_engine(ufrag: &str, addr: SocketAddr) -> SettingEngine {
    let mut setting_engine = SettingEngine::default();
    setting_engine.set_ice_credentials(ufrag.to_owned(), ufrag.to_owned());
    setting_engine.set_multicast_dns_mode(MulticastDnsMode::Disabled);
    setting_engine.set_network_types(vec![match addr {
        SocketAddr::V4(_) => NetworkType::Udp4,
        SocketAddr::V6(_) => NetworkType::Udp6,
    }]);
    setting_engine
}

#[allow(clippy::result_large_err)]
async fn create_noise_data_channel(
    connection: &Arc<dyn PeerConnection>,
) -> Result<Arc<dyn DataChannel>, Error> {
    Ok(connection
        .create_data_channel(
            "",
            Some(RTCDataChannelInit {
                negotiated: Some(0),
                ..RTCDataChannelInit::default()
            }),
        )
        .await?)
}

#[allow(clippy::result_large_err)]
async fn await_noise_data_channel_open(
    data_channel: Arc<dyn DataChannel>,
) -> Result<Arc<dyn DataChannel>, Error> {
    match futures::future::select(
        Box::pin(await_data_channel_open(data_channel)),
        Delay::new(Duration::from_secs(10)),
    )
    .await
    {
        Either::Left((result, _)) => result,
        Either::Right(((), _)) => Err(Error::Internal(
            "data channel opening took longer than 10 seconds (see logs)".into(),
        )),
    }
}

#[allow(clippy::result_large_err)]
async fn remote_fingerprint(connection: &dyn PeerConnection) -> Result<Fingerprint, Error> {
    let report = connection
        .get_stats(Instant::now(), StatsSelector::None)
        .await;
    let certificate_id = report
        .iter()
        .find_map(|entry| match entry {
            RTCStatsReportEntry::Transport(transport)
                if !transport.remote_certificate_id.is_empty() =>
            {
                Some(transport.remote_certificate_id.clone())
            }
            _ => None,
        })
        .ok_or_else(|| Error::Internal("remote certificate is missing from WebRTC stats".into()))?;
    let fingerprint = report
        .iter()
        .find_map(|entry| match entry {
            RTCStatsReportEntry::Certificate(certificate)
                if certificate.stats.id == certificate_id =>
            {
                Some(certificate.fingerprint.clone())
            }
            _ => None,
        })
        .ok_or_else(|| {
            Error::Internal("remote certificate fingerprint is missing from WebRTC stats".into())
        })?;

    crate::tokio::Fingerprint::try_from_rtc_dtls(&RTCDtlsFingerprint {
        algorithm: "sha-256".into(),
        value: fingerprint,
    })
    .map(|fingerprint| fingerprint.into_inner())
    .ok_or_else(|| Error::Internal("invalid remote SHA-256 certificate fingerprint".into()))
}
