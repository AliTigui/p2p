//! Optional SOCKS5-only outbound transport.
//!
//! This module implements no anonymity protocol of its own. It hands target
//! hostnames to a user-configured SOCKS5 proxy so DNS is performed by the
//! proxy, and it exposes no listener. It is intended for a locally running
//! Tor SOCKS5 service, but the app cannot verify that the proxy is Tor or that
//! an observer cannot correlate traffic.

use std::borrow::Cow;
use std::io;
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};
use std::pin::Pin;
use std::task::{Context, Poll};

use libp2p::core::transport::{DialOpts, ListenerId, Transport, TransportError, TransportEvent};
use libp2p::futures::FutureExt;
use libp2p::futures::future::BoxFuture;
use libp2p::multiaddr::{Multiaddr, Protocol};
use tokio::net::TcpStream as TokioTcpStream;
use tokio_socks::TargetAddr;
use tokio_socks::io::Compat as Socks5Compat;
use tokio_socks::tcp::Socks5Stream;
use tokio_util::compat::TokioAsyncReadCompatExt;

/// A TCP transport that can only dial through a fixed SOCKS5 proxy.
///
/// `listen_on` always fails: proxy mode has no direct inbound path. A relay
/// listener, if configured, is handled by libp2p's relay transport above this
/// one; its reservation dial also goes through this SOCKS5 transport.
#[derive(Debug, Clone, Copy)]
pub(super) struct Socks5OnlyTransport {
    proxy: SocketAddr,
}

impl Socks5OnlyTransport {
    pub(super) fn new(proxy: SocketAddr) -> Self {
        Self { proxy }
    }
}

/// Convert a libp2p dial address into an explicit SOCKS5 target without local
/// name resolution. `/dnsaddr` is rejected because its resolution would be
/// application-defined and could leak a lookup outside the proxy.
fn socks5_target(address: &Multiaddr) -> Option<TargetAddr<'static>> {
    let protocols: Vec<_> = address.iter().collect();
    let without_peer = match protocols.last() {
        Some(Protocol::P2p(_)) => &protocols[..protocols.len() - 1],
        _ => &protocols[..],
    };
    if without_peer
        .iter()
        .any(|protocol| matches!(protocol, Protocol::P2pCircuit))
    {
        return None;
    }
    match without_peer {
        [Protocol::Ip4(ip), Protocol::Tcp(port)] => Some(TargetAddr::Ip(SocketAddr::V4(
            SocketAddrV4::new(*ip, *port),
        ))),
        [Protocol::Ip6(ip), Protocol::Tcp(port)] => Some(TargetAddr::Ip(SocketAddr::V6(
            SocketAddrV6::new(*ip, *port, 0, 0),
        ))),
        [Protocol::Dns4(host), Protocol::Tcp(port)]
        | [Protocol::Dns6(host), Protocol::Tcp(port)] => {
            Some(TargetAddr::Domain(Cow::Owned(host.to_string()), *port))
        }
        _ => None,
    }
}

impl Transport for Socks5OnlyTransport {
    type Output = Socks5Stream<Socks5Compat<tokio_util::compat::Compat<TokioTcpStream>>>;
    type Error = io::Error;
    type Dial = BoxFuture<'static, Result<Self::Output, Self::Error>>;
    type ListenerUpgrade = BoxFuture<'static, Result<Self::Output, Self::Error>>;

    fn listen_on(
        &mut self,
        _id: ListenerId,
        _addr: Multiaddr,
    ) -> Result<(), TransportError<Self::Error>> {
        Err(TransportError::Other(io::Error::other(
            "SOCKS5-only route has no direct listener",
        )))
    }

    fn remove_listener(&mut self, _id: ListenerId) -> bool {
        false
    }

    fn dial(
        &mut self,
        address: Multiaddr,
        _opts: DialOpts,
    ) -> Result<Self::Dial, TransportError<Self::Error>> {
        let target = socks5_target(&address)
            .ok_or_else(|| TransportError::MultiaddrNotSupported(address))?
            .to_owned();
        let proxy = self.proxy;
        Ok(async move {
            // tokio-socks' Compat adapts futures-io sockets to its tokio IO
            // trait. Tokio's TcpStream must first be adapted to futures-io so
            // the resulting Socks5Stream also satisfies libp2p's futures-io
            // upgrade traits.
            let socket = TokioTcpStream::connect(proxy).await?.compat();
            Socks5Stream::connect_with_socket(Socks5Compat::new(socket), target)
                .await
                .map_err(|error| io::Error::other(error.to_string()))
        }
        .boxed())
    }

    fn poll(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<TransportEvent<Self::ListenerUpgrade, Self::Error>> {
        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::time::{Duration, timeout};

    fn target(input: &str) -> Option<TargetAddr<'static>> {
        socks5_target(&Multiaddr::from_str(input).expect("valid multiaddr"))
    }

    fn dial_opts() -> DialOpts {
        DialOpts {
            role: libp2p::core::Endpoint::Dialer,
            port_use: libp2p::core::transport::PortUse::Reuse,
        }
    }

    #[test]
    fn ip_targets_are_passed_to_the_proxy_without_local_resolution() {
        assert_eq!(
            target("/ip4/127.0.0.1/tcp/9051"),
            Some(TargetAddr::Ip(
                "127.0.0.1:9051".parse().expect("socket addr")
            ))
        );
        assert_eq!(
            target("/ip6/::1/tcp/9052"),
            Some(TargetAddr::Ip("[::1]:9052".parse().expect("socket addr")))
        );
    }

    #[test]
    fn dns_targets_are_forwarded_as_domains_for_proxy_side_resolution() {
        assert_eq!(
            target("/dns4/example.onion/tcp/443"),
            Some(TargetAddr::Domain(
                Cow::Owned("example.onion".to_owned()),
                443
            ))
        );
        assert_eq!(
            target("/dns6/example.onion/tcp/443"),
            Some(TargetAddr::Domain(
                Cow::Owned("example.onion".to_owned()),
                443
            ))
        );
    }

    #[test]
    fn unsupported_targets_fail_closed() {
        assert!(target("/dnsaddr/example.onion/tcp/443").is_none());
        assert!(target("/ip4/127.0.0.1/udp/9051").is_none());
        assert!(target("/ip4/127.0.0.1/tcp/9051/p2p-circuit").is_none());
        assert!(target("/ip4/127.0.0.1").is_none());
    }

    #[test]
    fn proxy_mode_never_accepts_a_direct_listener() {
        let transport = Socks5OnlyTransport::new("127.0.0.1:9050".parse().expect("proxy addr"));
        let mut transport = transport;
        let error = transport
            .listen_on(
                ListenerId::next(),
                Multiaddr::from_str("/ip4/0.0.0.0/tcp/0").expect("listen address"),
            )
            .expect_err("direct listener must fail");
        match error {
            TransportError::Other(reason) => {
                assert!(
                    reason.to_string().contains("no direct listener"),
                    "listener must be refused by the SOCKS5-only transport"
                );
            }
            other => panic!("unexpected listener error: {other:?}"),
        }
        assert!(!transport.remove_listener(ListenerId::next()));
    }

    #[test]
    fn unsupported_dial_addresses_fail_before_creating_a_dial_future() {
        let mut transport = Socks5OnlyTransport::new("127.0.0.1:9050".parse().expect("proxy addr"));
        for input in [
            "/dnsaddr/example.onion/tcp/443",
            "/ip4/127.0.0.1/udp/9051",
            "/ip4/127.0.0.1/tcp/9051/p2p-circuit",
            "/ip4/127.0.0.1",
        ] {
            let address = Multiaddr::from_str(input).expect("valid multiaddr");
            assert!(
                transport.dial(address, dial_opts()).is_err(),
                "unsupported target {input} must fail closed"
            );
        }
    }

    #[tokio::test]
    async fn dns_target_reaches_the_proxy_as_a_domain_not_a_local_lookup() {
        let proxy_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("proxy listener");
        let proxy_addr = proxy_listener.local_addr().expect("proxy address");
        let server = tokio::spawn(async move {
            let (mut stream, _) = proxy_listener.accept().await.expect("proxy accept");
            let mut greeting = [0u8; 2];
            stream.read_exact(&mut greeting).await.expect("greeting");
            assert_eq!(greeting[0], 5, "SOCKS5 greeting version");
            assert!(greeting[1] > 0, "SOCKS5 greeting must offer a method");
            let mut methods = vec![0u8; greeting[1] as usize];
            stream.read_exact(&mut methods).await.expect("methods");
            stream
                .write_all(&[5, 0])
                .await
                .expect("no-auth method selection");

            let mut request = [0u8; 4];
            stream
                .read_exact(&mut request)
                .await
                .expect("request header");
            assert_eq!(request, [5, 1, 0, 3], "expected domain CONNECT request");
            let mut length = [0u8; 1];
            stream.read_exact(&mut length).await.expect("domain length");
            let mut domain = vec![0u8; length[0] as usize];
            stream.read_exact(&mut domain).await.expect("domain bytes");
            let mut port = [0u8; 2];
            stream.read_exact(&mut port).await.expect("port bytes");
            (
                String::from_utf8(domain).expect("ascii domain"),
                u16::from_be_bytes(port),
            )
        });

        let mut transport = Socks5OnlyTransport::new(proxy_addr);
        let address =
            Multiaddr::from_str("/dns4/example.onion/tcp/443").expect("domain target address");
        let dial = transport.dial(address, dial_opts()).expect("dial future");
        // The fake proxy drops the connection instead of replying, so the dial
        // must fail rather than silently taking a direct route.
        assert!(
            timeout(Duration::from_secs(5), dial)
                .await
                .expect("proxy dial timed out")
                .is_err()
        );
        let (domain, port) = timeout(Duration::from_secs(5), server)
            .await
            .expect("proxy server task timed out")
            .expect("proxy server task");
        assert_eq!(domain, "example.onion");
        assert_eq!(port, 443);
    }

    #[tokio::test]
    async fn failed_proxy_handshake_never_falls_back_to_the_target() {
        let target_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("target listener");
        let target_addr = target_listener.local_addr().expect("target address");
        let proxy_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("proxy listener");
        let proxy_addr = proxy_listener.local_addr().expect("proxy address");
        let proxy_task = tokio::spawn(async move {
            let (_socket, _) = proxy_listener.accept().await.expect("proxy accept");
            // Drop the socket without a valid SOCKS5 reply.
        });

        let mut transport = Socks5OnlyTransport::new(proxy_addr);
        let address = Multiaddr::from_str(&format!(
            "/ip4/{}/tcp/{}",
            target_addr.ip(),
            target_addr.port()
        ))
        .expect("target address");
        let dial = transport.dial(address, dial_opts()).expect("dial future");
        assert!(
            timeout(Duration::from_secs(5), dial)
                .await
                .expect("proxy dial timed out")
                .is_err(),
            "a broken SOCKS5 handshake must fail the dial"
        );
        proxy_task.await.expect("proxy task");
        assert!(
            timeout(Duration::from_millis(200), target_listener.accept())
                .await
                .is_err(),
            "direct fallback connected to the target"
        );
    }
}
