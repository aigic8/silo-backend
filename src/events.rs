use axum::extract::ws::rejection::WebSocketUpgradeRejection;
use axum::extract::ws::{Message, WebSocket};
use axum::extract::{State, WebSocketUpgrade};
use axum::http::StatusCode;
use axum::response::Response;
use serde::Serialize;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use uuid::Uuid;

use crate::{ApiError, AppState, AuthUser};

/// Maximum lifetime of a single authenticated websocket connection. The
/// socket is closed after this age, forcing the client to reconnect, re-run
/// cookie authentication and fetch the latest vault. This satisfies the
/// "revalidate expiry/logout for long-lived sockets or limit lifetime"
/// requirement without a separate per-socket session poll.
pub const WS_MAX_LIFETIME: Duration = Duration::from_secs(30 * 60);

/// Per-socket outbound queue capacity. A subscriber that stops reading is
/// dropped once its queue fills; the client sees the socket close, reconnects
/// and fetches the latest vault instead of allowing unbounded memory growth.
pub const SUBSCRIBER_CHANNEL_CAPACITY: usize = 64;

/// Server-to-client event. Only invalidation metadata is sent: version number,
/// never plaintext or ciphertext.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerEvent {
    VaultChanged { version: i64 },
}

/// In-process pub/sub hub keyed by user id. This is intentionally a
/// single-instance broadcast: a vault change is delivered only to sockets on
/// the same process. Deploying multiple backend replicas requires an external
/// fan-out (for example Redis pub/sub); see README.
#[derive(Clone, Default)]
pub struct EventHub {
    inner: Arc<EventHubInner>,
}

#[derive(Default)]
struct EventHubInner {
    subscribers: Mutex<HashMap<Uuid, HashMap<u64, Sender<ServerEvent>>>>,
    next_id: AtomicU64,
}

impl EventHub {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a socket for a user. Returns the subscription id and the
    /// receiver end. The id must be passed back to [`Self::unsubscribe`] when
    /// the socket closes.
    pub fn subscribe(&self, user_id: Uuid) -> (u64, Receiver<ServerEvent>) {
        let (sender, receiver) = channel(SUBSCRIBER_CHANNEL_CAPACITY);
        let id = self.inner.next_id.fetch_add(1, Ordering::Relaxed);

        let mut subscribers = self.inner.subscribers.lock().expect("event hub poisoned");
        subscribers.entry(user_id).or_default().insert(id, sender);

        (id, receiver)
    }

    pub fn unsubscribe(&self, user_id: Uuid, subscription_id: u64) {
        let mut subscribers = self.inner.subscribers.lock().expect("event hub poisoned");
        let mut remove_user = false;
        if let Some(user_subscriptions) = subscribers.get_mut(&user_id) {
            user_subscriptions.remove(&subscription_id);
            remove_user = user_subscriptions.is_empty();
        }
        if remove_user {
            subscribers.remove(&user_id);
        }
    }

    /// Publish a `vault_changed` invalidation to every socket belonging to the
    /// given user. Sockets belonging to any other user are never contacted.
    ///
    /// Sends are non-blocking (`try_send`). A disconnected subscriber or one
    /// whose bounded queue is full is removed and its channel closed; the
    /// associated socket loop observes the closure and exits rather than
    /// hanging on a slow peer.
    pub fn publish_vault_changed(&self, user_id: Uuid, version: i64) {
        let event = ServerEvent::VaultChanged { version };

        let mut subscribers = self.inner.subscribers.lock().expect("event hub poisoned");
        let Some(user_subscriptions) = subscribers.get_mut(&user_id) else {
            return;
        };

        let mut dropped = Vec::new();
        for (&subscription_id, sender) in user_subscriptions.iter() {
            match sender.try_send(event.clone()) {
                Ok(()) => {}
                Err(TrySendError::Full(_)) | Err(TrySendError::Closed(_)) => {
                    dropped.push(subscription_id);
                }
            }
        }

        for subscription_id in dropped {
            user_subscriptions.remove(&subscription_id);
        }
        if user_subscriptions.is_empty() {
            subscribers.remove(&user_id);
        }
    }
}

/// `GET /api/events` websocket handler. Cookie authentication and the required
/// allowed-Origin check happen before the upgrade; after the upgrade the only
/// outgoing messages are `vault_changed` invalidations for this user.
pub async fn events_ws(
    State(state): State<AppState>,
    user: AuthUser,
    ws: Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
) -> Result<Response, ApiError> {
    let ws =
        ws.map_err(|_| ApiError::new(StatusCode::UPGRADE_REQUIRED, "WebSocket upgrade required"))?;
    Ok(ws.on_upgrade(move |socket| handle_socket(socket, state, user.user_id)))
}

async fn handle_socket(mut socket: WebSocket, state: AppState, user_id: Uuid) {
    let (subscription_id, mut receiver) = state.events.subscribe(user_id);

    let lifetime = tokio::time::sleep(WS_MAX_LIFETIME);
    tokio::pin!(lifetime);

    loop {
        tokio::select! {
            incoming = socket.recv() => {
                match incoming {
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Ok(Message::Ping(_))) => continue,
                    Some(Ok(_)) => continue,
                    Some(Err(_)) => break,
                }
            }
            event = receiver.recv() => {
                let Some(event) = event else { break };
                let Ok(text) = serde_json::to_string(&event) else { continue };
                if socket.send(Message::Text(text.into())).await.is_err() {
                    break;
                }
            }
            _ = &mut lifetime => {
                let _ = socket.send(Message::Close(None)).await;
                break;
            }
        }
    }

    state.events.unsubscribe(user_id, subscription_id);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_event_serializes_to_wire_shape() {
        let event = ServerEvent::VaultChanged { version: 7 };
        assert_eq!(
            serde_json::to_string(&event).expect("serializes"),
            r#"{"type":"vault_changed","version":7}"#
        );
    }

    #[tokio::test]
    async fn hub_is_scoped_to_a_single_user() {
        let hub = EventHub::new();
        let alice = Uuid::new_v4();
        let bob = Uuid::new_v4();

        let (alice_id, mut alice_rx) = hub.subscribe(alice);
        let (bob_id, mut bob_rx) = hub.subscribe(bob);

        hub.publish_vault_changed(alice, 1);
        assert_eq!(
            alice_rx.recv().await,
            Some(ServerEvent::VaultChanged { version: 1 })
        );
        assert!(bob_rx.try_recv().is_err());

        hub.unsubscribe(alice, alice_id);
        hub.unsubscribe(bob, bob_id);
    }

    #[tokio::test]
    async fn unsubscribed_socket_stops_receiving_events() {
        let hub = EventHub::new();
        let user_id = Uuid::new_v4();
        let (id, mut rx) = hub.subscribe(user_id);
        hub.unsubscribe(user_id, id);

        hub.publish_vault_changed(user_id, 2);
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn slow_subscriber_is_dropped_when_queue_overflows() {
        let hub = EventHub::new();
        let user_id = Uuid::new_v4();
        let (id, mut rx) = hub.subscribe(user_id);

        for version in 1..=(SUBSCRIBER_CHANNEL_CAPACITY as i64 + 1) {
            hub.publish_vault_changed(user_id, version);
        }

        // The channel is bounded, so the overflow publish drops the
        // subscriber and closes the receiver rather than growing without
        // bound. Drain the queued events, then observe closure.
        for _ in 0..SUBSCRIBER_CHANNEL_CAPACITY {
            assert!(rx.recv().await.is_some());
        }
        assert_eq!(rx.recv().await, None);

        // Cleanup is idempotent after the hub already removed the subscriber.
        hub.unsubscribe(user_id, id);
    }
}
