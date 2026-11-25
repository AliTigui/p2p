//! Bounded pre-authentication admission for direct TCP connections.
//!
//! libp2p's connection-limits behaviour sees a connection only after the
//! transport emits an inbound connection. This wrapper filters the earlier
//! [`TransportEvent::Incoming`], before Noise authentication, so many stalled
//! sockets from one source IP cannot consume the global pending socket budget.
//!
//! The counter is held by the listener-upgrade future and is released when the
//! upgrade succeeds, fails, or is dropped. Established connections remain
//! governed by the existing post-authentication per-IP limit.

use std::collections::HashMap;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use libp2p::core::transport::{DialOpts, ListenerId, Transport, TransportError, TransportEvent};
use libp2p::futures::FutureExt;
use libp2p::futures::future::BoxFuture;
use libp2p::multiaddr::{Multiaddr, Protocol};

#[derive(Debug)]
struct PendingState {
    limit: usize,
    counts: HashMap<IpAddr, usize>,
}

impl PendingState {
    fn new(limit: usize) -> Self {
        Self {
            limit: limit.max(1),
            counts: HashMap::new(),
        }
    }

    fn admit(&mut self, ip: IpAddr) -> bool {
        let count = self.counts.entry(ip).or_insert(0);
        if *count >= self.limit {
            return false;
        }
        *count += 1;
        true
    }

    fn release(&mut self, ip: IpAddr) {
        let remove = match self.counts.get_mut(&ip) {
            Some(count) => {
                *count = count.saturating_sub(1);
                *count == 0
            }
            None => false,
        };
        if remove {
            self.counts.remove(&ip);
        }
    }

    #[cfg(test)]
    fn count(&self, ip: IpAddr) -> usize {
        self.counts.get(&ip).copied().unwrap_or(0)
    }
}

/// One admitted pre-authentication socket. The slot is returned when this
/// guard is dropped, including when a stalled upgrade is cancelled at shutdown.
struct PendingGuard {
    state: Arc<Mutex<PendingState>>,
    ip: IpAddr,
}

impl Drop for PendingGuard {
    fn drop(&mut self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.release(self.ip);
    }
}

/// Wraps an upgraded transport and admits at most `limit` concurrent
/// unauthenticated sockets from one observed IP address.
pub(super) struct PerIpPendingTransport<T> {
    inner: T,
    state: Arc<Mutex<PendingState>>,
}

impl<T> PerIpPendingTransport<T> {
    pub(super) fn new(inner: T, limit: usize) -> Self {
        Self {
            inner,
            state: Arc::new(Mutex::new(PendingState::new(limit))),
        }
    }
}

fn ip_from_send_back(addr: &Multiaddr) -> Option<IpAddr> {
    addr.iter().find_map(|protocol| match protocol {
        Protocol::Ip4(ip) => Some(IpAddr::V4(ip)),
        Protocol::Ip6(ip) => Some(IpAddr::V6(ip)),
        _ => None,
    })
}

impl<T> Transport for PerIpPendingTransport<T>
where
    T: Transport + Unpin + Send + 'static,
    T::Output: 'static,
    T::Error: 'static,
    T::Dial: Send,
    T::ListenerUpgrade: Send + 'static,
{
    type Output = T::Output;
    type Error = T::Error;
    type Dial = T::Dial;
    type ListenerUpgrade = BoxFuture<'static, Result<Self::Output, Self::Error>>;

    fn listen_on(
        &mut self,
        id: ListenerId,
        addr: Multiaddr,
    ) -> Result<(), TransportError<Self::Error>> {
        self.inner.listen_on(id, addr)
    }

    fn remove_listener(&mut self, id: ListenerId) -> bool {
        self.inner.remove_listener(id)
    }

    fn dial(
        &mut self,
        addr: Multiaddr,
        opts: DialOpts,
    ) -> Result<Self::Dial, TransportError<Self::Error>> {
        self.inner.dial(addr, opts)
    }

    fn poll(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<TransportEvent<Self::ListenerUpgrade, Self::Error>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(TransportEvent::Incoming {
                listener_id,
                upgrade,
                local_addr,
                send_back_addr,
            }) => {
                let Some(ip) = ip_from_send_back(&send_back_addr) else {
                    // Fail closed: an inbound address without a concrete IP
                    // cannot be charged to a per-IP budget, so drop it.
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                };

                let guard = {
                    let mut state = this
                        .state
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    if state.admit(ip) {
                        Some(PendingGuard {
                            state: Arc::clone(&this.state),
                            ip,
                        })
                    } else {
                        None
                    }
                };

                let Some(guard) = guard else {
                    // Dropping `upgrade` closes the raw socket before any
                    // Noise negotiation. Wake once so the next buffered
                    // inbound event is processed without a busy loop here.
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                };

                let upgrade = async move {
                    let result = upgrade.await;
                    drop(guard);
                    result
                }
                .boxed();

                Poll::Ready(TransportEvent::Incoming {
                    listener_id,
                    upgrade,
                    local_addr,
                    send_back_addr,
                })
            }
            Poll::Ready(TransportEvent::NewAddress {
                listener_id,
                listen_addr,
            }) => Poll::Ready(TransportEvent::NewAddress {
                listener_id,
                listen_addr,
            }),
            Poll::Ready(TransportEvent::AddressExpired {
                listener_id,
                listen_addr,
            }) => Poll::Ready(TransportEvent::AddressExpired {
                listener_id,
                listen_addr,
            }),
            Poll::Ready(TransportEvent::ListenerError { listener_id, error }) => {
                Poll::Ready(TransportEvent::ListenerError { listener_id, error })
            }
            Poll::Ready(TransportEvent::ListenerClosed {
                listener_id,
                reason,
            }) => Poll::Ready(TransportEvent::ListenerClosed {
                listener_id,
                reason,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;

    fn guard_for(state: &Arc<Mutex<PendingState>>, ip: IpAddr) -> Option<PendingGuard> {
        let mut inner = state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if inner.admit(ip) {
            Some(PendingGuard {
                state: Arc::clone(state),
                ip,
            })
        } else {
            None
        }
    }

    #[test]
    fn admits_up_to_the_limit_and_releases_on_drop() {
        let state = Arc::new(Mutex::new(PendingState::new(2)));
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);

        let first = guard_for(&state, ip).expect("first socket admitted");
        let second = guard_for(&state, ip).expect("second socket admitted");
        assert!(
            guard_for(&state, ip).is_none(),
            "third socket must be denied"
        );
        assert_eq!(state.lock().unwrap().count(ip), 2);

        drop(first);
        assert_eq!(state.lock().unwrap().count(ip), 1);
        let replacement = guard_for(&state, ip).expect("released slot is reusable");
        drop(second);
        drop(replacement);
        assert_eq!(state.lock().unwrap().count(ip), 0);
    }

    #[test]
    fn different_source_addresses_have_independent_budgets() {
        let state = Arc::new(Mutex::new(PendingState::new(1)));
        let v4 = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let v6 = IpAddr::V6(Ipv6Addr::LOCALHOST);

        let first = guard_for(&state, v4).expect("IPv4 socket admitted");
        let second = guard_for(&state, v6).expect("IPv6 socket admitted");
        assert!(guard_for(&state, v4).is_none(), "IPv4 budget is full");
        drop(first);
        drop(second);
    }

    #[test]
    fn send_back_parser_only_uses_concrete_ip_protocols() {
        let ip4 = Multiaddr::from_str("/ip4/127.0.0.1/tcp/4001").expect("valid multiaddr");
        let ip6 = Multiaddr::from_str("/ip6/::1/tcp/4001").expect("valid multiaddr");
        let dns = Multiaddr::from_str("/dns4/example.invalid/tcp/4001").expect("valid multiaddr");
        let circuit = Multiaddr::from_str("/p2p-circuit").expect("valid multiaddr");

        assert_eq!(
            ip_from_send_back(&ip4),
            Some(IpAddr::V4(Ipv4Addr::LOCALHOST))
        );
        assert_eq!(
            ip_from_send_back(&ip6),
            Some(IpAddr::V6(Ipv6Addr::LOCALHOST))
        );
        assert_eq!(ip_from_send_back(&dns), None);
        assert_eq!(ip_from_send_back(&circuit), None);
    }
}
