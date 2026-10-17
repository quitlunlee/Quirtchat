//! Bounded request/response transport. Identity-to-contact authorization belongs to the app.

use std::{io, sync::Arc, time::Duration};

use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use iroh::{
    Endpoint, EndpointAddr, RelayMode, SecretKey,
    endpoint::{
        Builder, Connection, PortmapperConfig, QuicTransportConfig, RecvStream, SendStream, presets,
    },
};
use serde::{Serialize, de::DeserializeOwned};
use tokio::{
    sync::{Mutex, Semaphore, mpsc, oneshot},
    task::{JoinHandle, JoinSet},
    time::{Instant, sleep_until, timeout},
};
use url::Url;

use crate::model::{MAX_FRAME_BYTES, Request, Response};

const ALPN: &[u8] = b"clichat/rpc/1";
const MAX_TICKET_BYTES: usize = 16 * 1024;
const CHUNK_BYTES: usize = 16 * 1024;
const WINDOW_BYTES: u32 = 64 * 1024;
// Endpoint initialization includes TLS and OS networking setup, not a peer RPC.
// Keep its deadline independent of a caller's short per-request retry budget.
const BIND_TIMEOUT: Duration = Duration::from_secs(15);

/// Shared limits across incoming and outgoing application requests.
#[derive(Clone, Copy, Debug)]
pub struct TransportLimits {
    pub max_inflight: usize,
    pub request_timeout: Duration,
    /// Combined application bytes read and written per second, excluding QUIC/TLS overhead.
    /// QUIC may buffer up to a bounded receive window ahead of application reads.
    pub bytes_per_second: u32,
}

impl Default for TransportLimits {
    fn default() -> Self {
        Self {
            max_inflight: 8,
            request_timeout: Duration::from_secs(10),
            bytes_per_second: 256 * 1024,
        }
    }
}

#[derive(Debug)]
pub struct Incoming {
    /// Authenticated iroh endpoint ID, not the contact's separate signing identity.
    pub peer_id: String,
    pub request: Request,
    pub reply: oneshot::Sender<Response>,
}

pub struct Transport {
    endpoint: Endpoint,
    incoming: Option<mpsc::Receiver<Incoming>>,
    accept_task: JoinHandle<()>,
    permits: Arc<Semaphore>,
    limiter: Arc<ByteLimiter>,
    limits: TransportLimits,
    strict_proxy: bool,
}

impl Transport {
    pub async fn bind(secret: [u8; 32], proxy: Option<&str>) -> Result<Self> {
        Self::bind_with_limits(secret, proxy, TransportLimits::default()).await
    }

    pub async fn bind_with_limits(
        secret: [u8; 32],
        proxy: Option<&str>,
        limits: TransportLimits,
    ) -> Result<Self> {
        // Empty deliberately excludes DNS/Pkarr publication and lookup. Tickets and PEX
        // supply addresses. Shared n0 relays provide prototype connectivity, not storage.
        let mut builder = base_builder(secret).relay_mode(RelayMode::Default);
        if let Some(proxy) = proxy {
            let proxy = validate_proxy(proxy)?;
            // Never retain an IP transport that could bypass the configured proxy.
            builder = builder.clear_ip_transports().proxy_url(proxy);
        }
        Self::from_builder(builder, proxy.is_some(), limits).await
    }

    async fn from_builder(
        builder: Builder,
        strict_proxy: bool,
        limits: TransportLimits,
    ) -> Result<Self> {
        ensure!(
            (1..=8).contains(&limits.max_inflight),
            "inflight limit must be between 1 and 8"
        );
        ensure!(
            !limits.request_timeout.is_zero(),
            "request timeout must be positive"
        );
        ensure!(
            limits.bytes_per_second > 0,
            "bandwidth limit must be positive"
        );
        let endpoint = timeout(BIND_TIMEOUT, builder.bind())
            .await
            .context("transport bind timed out")?
            .context("could not bind transport")?;
        let permits = Arc::new(Semaphore::new(limits.max_inflight));
        let limiter = Arc::new(ByteLimiter::new(limits.bytes_per_second));
        let (sender, incoming) = mpsc::channel(limits.max_inflight);
        let accept_task = tokio::spawn(accept_loop(
            endpoint.clone(),
            sender,
            permits.clone(),
            limiter.clone(),
            limits,
        ));
        Ok(Self {
            endpoint,
            incoming: Some(incoming),
            accept_task,
            permits,
            limiter,
            limits,
            strict_proxy,
        })
    }

    pub fn take_incoming(&mut self) -> Option<mpsc::Receiver<Incoming>> {
        self.incoming.take()
    }

    /// Returns the current addresses; callers should regenerate tickets after network changes.
    /// An offline proxy endpoint has no usable ticket until a relay becomes available.
    pub fn ticket(&self) -> Result<String> {
        let addr = self.endpoint.addr();
        ensure!(!addr.is_empty(), "transport has no reachable address yet");
        encode_ticket(&addr)
    }

    pub fn endpoint_id(&self) -> String {
        self.endpoint.id().to_string()
    }

    /// Optional startup wait before publishing an invitation containing a home relay.
    pub async fn online(&self) -> Result<()> {
        timeout(self.limits.request_timeout, self.endpoint.online())
            .await
            .context("relay unavailable; transport remains offline")?;
        Ok(())
    }

    pub async fn request(&self, ticket: &str, request: Request) -> Result<Response> {
        let mut addr = decode_ticket(ticket)?;
        if self.strict_proxy {
            // Strip peer-supplied IPs too, so strict mode cannot accidentally pass them on.
            addr = addr
                .relay_urls()
                .cloned()
                .fold(EndpointAddr::new(addr.id), |addr, relay| {
                    addr.with_relay_url(relay)
                });
            ensure!(!addr.is_empty(), "proxy mode requires a peer relay address");
        }
        let _permit = self
            .permits
            .clone()
            .try_acquire_owned()
            .context("transport is busy; retry later")?;
        let bytes = encode_frame(&request)?;
        timeout(self.limits.request_timeout, async {
            let connection = self
                .endpoint
                .connect(addr, ALPN)
                .await
                .context("could not connect to peer")?;
            // Closing on cancellation also prevents an abandoned request using resources.
            let connection = CloseOnDrop(connection);
            let (mut send, mut recv) = connection.0.open_bi().await?;
            write_frame(&mut send, &bytes, &self.limiter).await?;
            let response = read_frame(&mut recv, &self.limiter).await?;
            Ok(response)
        })
        .await
        .context("request timed out")?
    }

    pub async fn close(&self) {
        self.accept_task.abort();
        self.endpoint.close().await;
    }
}

impl Drop for Transport {
    fn drop(&mut self) {
        // Dropping JoinSet inside the accept loop cancels all its handlers as well.
        self.accept_task.abort();
    }
}

fn base_builder(secret: [u8; 32]) -> Builder {
    let config = QuicTransportConfig::builder()
        .max_concurrent_bidi_streams(1_u32.into())
        .max_concurrent_uni_streams(0_u32.into())
        .stream_receive_window(WINDOW_BYTES.into())
        .receive_window(WINDOW_BYTES.into())
        .send_window(u64::from(WINDOW_BYTES))
        .datagram_receive_buffer_size(None)
        .build();
    Endpoint::builder(presets::Empty)
        // Empty intentionally omits even the mandatory TLS crypto provider.
        // Minimal supplies only that provider; it enables no relays or discovery.
        .preset(presets::Minimal)
        .secret_key(SecretKey::from_bytes(&secret))
        .alpns(vec![ALPN.to_vec()])
        .clear_address_lookup()
        .portmapper_config(PortmapperConfig::Disabled)
        .transport_config(config)
}

fn validate_proxy(value: &str) -> Result<Url> {
    // Do not include the original URL in errors: it may contain proxy credentials.
    let proxy = Url::parse(value).map_err(|_| anyhow::anyhow!("invalid proxy URL"))?;
    ensure!(
        matches!(proxy.scheme(), "http" | "https"),
        "proxy must use http:// or https:// (HTTP CONNECT)"
    );
    ensure!(
        proxy.host().is_some() && proxy.port_or_known_default().is_some(),
        "proxy requires a host and port"
    );
    ensure!(
        proxy.path() == "/" && proxy.query().is_none() && proxy.fragment().is_none(),
        "proxy URL must not contain a path, query, or fragment"
    );
    Ok(proxy)
}

pub fn encode_ticket(addr: &EndpointAddr) -> Result<String> {
    let json = serde_json::to_vec(addr)?;
    ensure!(
        json.len() <= MAX_TICKET_BYTES * 3 / 4,
        "ticket is too large"
    );
    Ok(URL_SAFE_NO_PAD.encode(json))
}

pub fn decode_ticket(ticket: &str) -> Result<EndpointAddr> {
    ensure!(
        !ticket.is_empty() && ticket.len() <= MAX_TICKET_BYTES,
        "invalid ticket length"
    );
    let json = URL_SAFE_NO_PAD
        .decode(ticket)
        .context("invalid ticket encoding")?;
    let addr: EndpointAddr = serde_json::from_slice(&json).context("invalid endpoint ticket")?;
    ensure!(
        !addr.is_empty() && addr.addrs.len() <= 16,
        "ticket must contain between 1 and 16 addresses"
    );
    ensure!(
        addr.ip_addrs().count() + addr.relay_urls().count() == addr.addrs.len(),
        "unsupported ticket transport"
    );
    // No custom transports exist in this protocol. Require HTTPS public relay URLs so
    // untrusted PEX cannot inject credentials or plaintext relay connections.
    for relay in addr.relay_urls() {
        ensure!(
            relay.scheme() == "https"
                && relay.username().is_empty()
                && relay.password().is_none()
                && relay.host().is_some()
                && relay.query().is_none()
                && relay.fragment().is_none(),
            "invalid relay URL in ticket"
        );
    }
    Ok(addr)
}

pub fn ticket_endpoint_id(ticket: &str) -> Result<String> {
    Ok(decode_ticket(ticket)?.id.to_string())
}

async fn accept_loop(
    endpoint: Endpoint,
    sender: mpsc::Sender<Incoming>,
    permits: Arc<Semaphore>,
    limiter: Arc<ByteLimiter>,
    limits: TransportLimits,
) {
    let mut handlers = JoinSet::new();
    loop {
        tokio::select! {
            _ = sender.closed() => break,
            Some(_) = handlers.join_next(), if !handlers.is_empty() => {},
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else { break };
                let Ok(permit) = permits.clone().try_acquire_owned() else {
                    incoming.refuse();
                    continue;
                };
                let sender = sender.clone();
                let limiter = limiter.clone();
                handlers.spawn(async move {
                    let _permit = permit;
                    // The deadline includes handshake, upload, application processing and reply.
                    let _ = timeout(limits.request_timeout, async {
                        let connection = CloseOnDrop(incoming.await?);
                        serve_request(&connection.0, sender, &limiter).await
                    }).await;
                });
            }
        }
    }
}

async fn serve_request(
    connection: &Connection,
    sender: mpsc::Sender<Incoming>,
    limiter: &ByteLimiter,
) -> Result<()> {
    let (mut send, mut recv) = connection.accept_bi().await?;
    let request = read_frame(&mut recv, limiter).await?;
    let (reply, response) = oneshot::channel();
    sender
        .send(Incoming {
            peer_id: connection.remote_id().to_string(),
            request,
            reply,
        })
        .await
        .map_err(|_| anyhow::anyhow!("application receiver closed"))?;
    let response = response.await.context("application dropped response")?;
    let bytes = match encode_frame(&response) {
        Ok(bytes) => bytes,
        Err(_) => encode_frame(&Response::Error(
            "response exceeds frame limit; request a smaller page".into(),
        ))?,
    };
    write_frame(&mut send, &bytes, limiter).await?;
    // The reader closes only after consuming the response. Closing immediately after
    // finish() can discard bytes that QUIC has acknowledged but the application hasn't read.
    connection.closed().await;
    Ok(())
}

struct CloseOnDrop(Connection);

impl Drop for CloseOnDrop {
    fn drop(&mut self) {
        self.0.close(0_u32.into(), b"request complete");
    }
}

struct ByteLimiter {
    bytes_per_second: u32,
    next: Mutex<Instant>,
}

impl ByteLimiter {
    fn new(bytes_per_second: u32) -> Self {
        Self {
            bytes_per_second,
            next: Mutex::new(Instant::now()),
        }
    }

    async fn consume(&self, bytes: usize) {
        let when = {
            let mut next = self.next.lock().await;
            let start = (*next).max(Instant::now());
            let duration = Duration::from_secs_f64(bytes as f64 / f64::from(self.bytes_per_second));
            *next = start + duration;
            *next
        };
        sleep_until(when).await;
    }
}

struct FrameBuffer(Vec<u8>);

impl io::Write for FrameBuffer {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.len() > MAX_FRAME_BYTES.saturating_sub(self.0.len()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "frame exceeds 2 MiB",
            ));
        }
        self.0.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn encode_frame(value: &impl Serialize) -> Result<Vec<u8>> {
    let mut out = FrameBuffer(Vec::new());
    serde_json::to_writer(&mut out, value).context("could not encode bounded frame")?;
    Ok(out.0)
}

async fn write_frame(send: &mut SendStream, bytes: &[u8], limiter: &ByteLimiter) -> Result<()> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_FRAME_BYTES,
        "invalid frame length"
    );
    limiter.consume(4).await;
    send.write_all(&(bytes.len() as u32).to_be_bytes()).await?;
    for chunk in bytes.chunks(CHUNK_BYTES) {
        limiter.consume(chunk.len()).await;
        send.write_all(chunk).await?;
    }
    send.finish()?;
    Ok(())
}

async fn read_frame<T: DeserializeOwned>(
    recv: &mut RecvStream,
    limiter: &ByteLimiter,
) -> Result<T> {
    let mut header = [0_u8; 4];
    limiter.consume(header.len()).await;
    recv.read_exact(&mut header).await?;
    let length = u32::from_be_bytes(header) as usize;
    ensure!(
        (1..=MAX_FRAME_BYTES).contains(&length),
        "invalid frame length"
    );
    let mut bytes = vec![0; length];
    for chunk in bytes.chunks_mut(CHUNK_BYTES) {
        limiter.consume(chunk.len()).await;
        recv.read_exact(chunk).await?;
    }
    let mut extra = [0_u8; 1];
    if recv.read(&mut extra).await?.is_some() {
        bail!("unexpected bytes after frame");
    }
    serde_json::from_slice(&bytes).context("invalid frame JSON")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    async fn local_transport(secret: [u8; 32], limits: TransportLimits) -> Result<Transport> {
        Transport::from_builder(
            base_builder(secret)
                .clear_ip_transports()
                .bind_addr("127.0.0.1:0")?,
            false,
            limits,
        )
        .await
    }

    pub(super) async fn local_ticket(transport: &Transport) -> Result<String> {
        for _ in 0..100 {
            if let Ok(ticket) = transport.ticket() {
                return Ok(ticket);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        bail!("local endpoint did not publish its address")
    }

    #[tokio::test]
    async fn local_endpoints_exchange_authenticated_request() -> Result<()> {
        let client = local_transport([1; 32], TransportLimits::default()).await?;
        let mut server = local_transport([2; 32], TransportLimits::default()).await?;
        let ticket = local_ticket(&server).await?;
        assert_eq!(ticket_endpoint_id(&ticket)?, server.endpoint_id());
        let mut incoming = server.take_incoming().unwrap();
        let expected_peer = client.endpoint_id();
        let handler = async {
            let incoming = incoming.recv().await.unwrap();
            assert_eq!(incoming.peer_id, expected_peer);
            assert!(matches!(incoming.request, Request::Peers));
            incoming
                .reply
                .send(Response::Peers(vec!["verified".into()]))
                .unwrap();
        };
        let (response, ()) = tokio::join!(client.request(&ticket, Request::Peers), handler);
        let response = response?;
        assert!(matches!(response, Response::Peers(peers) if peers == vec!["verified"]));
        client.close().await;
        server.close().await;
        Ok(())
    }

    #[tokio::test]
    async fn rejecting_proxy_cannot_fall_back_to_direct_peer() -> Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let proxy = format!("http://{}", listener.local_addr()?);
        let (observed, mut requests) = mpsc::channel(32);
        let proxy_task = tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let mut data = [0_u8; 4096];
                if let Ok(Ok(n)) = timeout(Duration::from_secs(1), stream.read(&mut data)).await {
                    let _ = observed.try_send(String::from_utf8_lossy(&data[..n]).to_string());
                    let _ = stream.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await;
                }
            }
        });
        let limits = TransportLimits {
            request_timeout: Duration::from_secs(2),
            ..Default::default()
        };
        let client = Transport::bind_with_limits([3; 32], Some(&proxy), limits).await?;
        assert_eq!(client.endpoint.addr().ip_addrs().count(), 0);
        let mut server = local_transport([4; 32], TransportLimits::default()).await?;
        let direct_ticket = local_ticket(&server).await?;
        let mut incoming = server.take_incoming().unwrap();
        assert!(
            client
                .request(&direct_ticket, Request::Peers)
                .await
                .is_err()
        );
        let addr = decode_ticket(&direct_ticket)?.with_relay_url("https://relay.invalid".parse()?);
        assert!(
            client
                .request(&encode_ticket(&addr)?, Request::Peers)
                .await
                .is_err()
        );
        assert!(
            timeout(Duration::from_millis(50), incoming.recv())
                .await
                .is_err()
        );
        let mut saw_connect = false;
        while let Ok(request) = requests.try_recv() {
            saw_connect |= request.starts_with("CONNECT ");
        }
        assert!(
            saw_connect,
            "configured proxy did not receive CONNECT traffic"
        );
        client.close().await;
        server.close().await;
        proxy_task.abort();
        Ok(())
    }

    #[test]
    fn rejects_unsupported_proxy_and_unbounded_frames() {
        assert!(validate_proxy("socks5://127.0.0.1:1080").is_err());
        assert!(validate_proxy("http://127.0.0.1:8080/path").is_err());
        assert!(validate_proxy("http://127.0.0.1:8080").is_ok());
        assert!(encode_frame(&Response::Error("x".repeat(MAX_FRAME_BYTES))).is_err());
        assert!(decode_ticket(&"a".repeat(MAX_TICKET_BYTES + 1)).is_err());
    }

    #[tokio::test]
    async fn limiter_shares_budget_across_callers() {
        let limiter = ByteLimiter::new(1000);
        let start = Instant::now();
        tokio::join!(limiter.consume(50), limiter.consume(50));
        assert!(start.elapsed() >= Duration::from_millis(100));
    }
}

#[cfg(test)]
#[path = "../tests/transport/closed_loop.rs"]
mod closed_loop;

#[cfg(test)]
#[path = "../tests/transport/media_loop.rs"]
mod media_loop;
