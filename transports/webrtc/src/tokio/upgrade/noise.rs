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

use futures::{AsyncRead, AsyncWrite, AsyncWriteExt};
use libp2p_core::{InboundUpgrade, OutboundUpgrade, ToProtocolsIter};
use libp2p_identity as identity;
use libp2p_identity::PeerId;
use libp2p_noise::{Keypair, NoiseConfig, X25519Spec};

use crate::tokio::fingerprint::Fingerprint;
use crate::tokio::Error;

pub async fn inbound<T>(
    id_keys: identity::Keypair,
    stream: T,
    client_fingerprint: Fingerprint,
    server_fingerprint: Fingerprint,
) -> Result<PeerId, Error>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let dh_keys = Keypair::<X25519Spec>::new()
        .into_authentic(&id_keys)
        .unwrap();
    let noise = NoiseConfig::xx(dh_keys)
        .with_prologue(noise_prologue(client_fingerprint, server_fingerprint));
    let protocol = noise.to_protocols_iter().next().unwrap();
    // Note the roles are reversed because it allows the server (webrtc connection responder) to
    // send application data 0.5 RTT earlier.
    let (peer_id, mut channel) = noise
        .into_authenticated()
        .upgrade_outbound(stream, protocol)
        .await?;

    channel.close().await?;

    Ok(peer_id)
}

pub async fn outbound<T>(
    id_keys: identity::Keypair,
    stream: T,
    server_fingerprint: Fingerprint,
    client_fingerprint: Fingerprint,
) -> Result<PeerId, Error>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let dh_keys = Keypair::<X25519Spec>::new()
        .into_authentic(&id_keys)
        .unwrap();
    let noise = NoiseConfig::xx(dh_keys)
        .with_prologue(noise_prologue(client_fingerprint, server_fingerprint));
    let protocol = noise.to_protocols_iter().next().unwrap();
    // Note the roles are reversed because it allows the server (webrtc connection responder) to
    // send application data 0.5 RTT earlier.
    let (peer_id, mut channel) = noise
        .into_authenticated()
        .upgrade_inbound(stream, protocol)
        .await?;

    channel.close().await?;

    Ok(peer_id)
}

pub fn noise_prologue(client_fingerprint: Fingerprint, server_fingerprint: Fingerprint) -> Vec<u8> {
    let client = client_fingerprint.to_multihash().to_bytes();
    let server = server_fingerprint.to_multihash().to_bytes();
    const PREFIX: &[u8] = b"libp2p-webrtc-noise:";
    let mut out = Vec::with_capacity(PREFIX.len() + client.len() + server.len());
    out.extend_from_slice(PREFIX);
    out.extend_from_slice(&client);
    out.extend_from_slice(&server);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn noise_prologue_tests() {
        let a = Fingerprint::raw(hex!(
            "3e79af40d6059617a0d83b83a52ce73b0c1f37a72c6043ad2969e2351bdca870"
        ));
        let b = Fingerprint::raw(hex!(
            "30fc9f469c207419dfdd0aab5f27a86c973c94e40548db9375cca2e915973b99"
        ));

        let prologue1 = noise_prologue(a, b);
        let prologue2 = noise_prologue(b, a);

        assert_eq!(hex::encode(prologue1), "6c69627032702d7765627274632d6e6f6973653a12203e79af40d6059617a0d83b83a52ce73b0c1f37a72c6043ad2969e2351bdca870122030fc9f469c207419dfdd0aab5f27a86c973c94e40548db9375cca2e915973b99");
        assert_eq!(hex::encode(prologue2), "6c69627032702d7765627274632d6e6f6973653a122030fc9f469c207419dfdd0aab5f27a86c973c94e40548db9375cca2e915973b9912203e79af40d6059617a0d83b83a52ce73b0c1f37a72c6043ad2969e2351bdca870");
    }
}
