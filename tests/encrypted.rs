//! DNS-over-TLS and DNS-over-HTTPS upstreams against local fake servers that
//! present a self-signed certificate for `dns.test`.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use hickory_proto::op::{Edns, Message, OpCode, Query};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, UdpSocket};
use tokio_rustls::TlsAcceptor;

use dns::config::UpstreamConfig;
use dns::upstream::{UpstreamAddr, Upstreams};

const ANSWER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 53);

struct Tls {
    acceptor: TlsAcceptor,
    client: rustls::ClientConfig,
}

fn tls(alpn: &[&[u8]]) -> Tls {
    let key = rcgen::generate_simple_self_signed(vec!["dns.test".to_string()]).unwrap();
    let cert: CertificateDer<'static> = key.cert.der().clone();
    let private = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.signing_key.serialize_der()));

    let mut server = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert.clone()], private)
        .unwrap();
    server.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();

    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert).unwrap();
    let client = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Tls {
        acceptor: TlsAcceptor::from(Arc::new(server)),
        client,
    }
}

fn answer(query: &Message, ip: Ipv4Addr) -> Vec<u8> {
    let mut response = Message::response(query.id, OpCode::Query);
    response.queries = query.queries.clone();
    if query.queries[0].query_type() == RecordType::A {
        response.add_answer(Record::from_rdata(
            query.queries[0].name().clone(),
            300,
            RData::A(A(ip)),
        ));
    }
    response.to_vec().unwrap()
}

/// What a fake server saw.
#[derive(Default)]
struct Seen {
    connections: AtomicUsize,
    query_lengths: Mutex<Vec<usize>>,
    query_ids: Mutex<Vec<u16>>,
}

impl Seen {
    fn record(&self, query: &[u8]) -> Message {
        let message = Message::from_vec(query).unwrap();
        self.query_lengths.lock().unwrap().push(query.len());
        self.query_ids.lock().unwrap().push(message.id);
        message
    }
}

async fn dot_server(tls: TlsAcceptor) -> (SocketAddr, Arc<Seen>) {
    dot_server_dropping(tls, 0).await
}

/// A DoT server that reads the query on its first `drop_first` connections
/// and then closes them without answering, as a flaky resolver does.
async fn dot_server_dropping(tls: TlsAcceptor, drop_first: usize) -> (SocketAddr, Arc<Seen>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(Seen::default());
    let state = Arc::clone(&seen);
    tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            let Ok(mut stream) = tls.accept(tcp).await else {
                continue;
            };
            let n = state.connections.fetch_add(1, Ordering::SeqCst);
            if n < drop_first {
                let len = stream.read_u16().await.unwrap();
                let mut buf = vec![0u8; len as usize];
                stream.read_exact(&mut buf).await.unwrap();
                stream.shutdown().await.ok();
                continue;
            }
            let state = Arc::clone(&state);
            tokio::spawn(async move {
                while let Ok(len) = stream.read_u16().await {
                    let mut buf = vec![0u8; len as usize];
                    stream.read_exact(&mut buf).await.unwrap();
                    let query = state.record(&buf);
                    let bytes = answer(&query, ANSWER);
                    stream.write_u16(bytes.len() as u16).await.unwrap();
                    stream.write_all(&bytes).await.unwrap();
                    stream.flush().await.unwrap();
                }
            });
        }
    });
    (addr, seen)
}

/// A minimal HTTP/1.1 DoH server: reads one POST per connection and answers it.
async fn doh_server(tls: TlsAcceptor) -> (SocketAddr, Arc<Seen>) {
    doh_server_dropping(tls, 0).await
}

/// A DoH server that hangs up without answering on its first `drop_first`
/// connections.
async fn doh_server_dropping(tls: TlsAcceptor, drop_first: usize) -> (SocketAddr, Arc<Seen>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(Seen::default());
    let state = Arc::clone(&seen);
    tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            let Ok(stream) = tls.accept(tcp).await else {
                continue;
            };
            let n = state.connections.fetch_add(1, Ordering::SeqCst);
            if n < drop_first {
                let mut stream = BufReader::new(stream);
                let mut line = String::new();
                stream.read_line(&mut line).await.ok();
                stream.into_inner().shutdown().await.ok();
                continue;
            }
            let state = Arc::clone(&state);
            tokio::spawn(async move {
                let mut stream = BufReader::new(stream);
                loop {
                    let mut request_line = String::new();
                    if stream.read_line(&mut request_line).await.unwrap_or(0) == 0 {
                        return;
                    }
                    assert!(
                        request_line.starts_with("POST /dns-query "),
                        "{request_line}"
                    );
                    let mut content_length = 0;
                    let mut content_type = String::new();
                    loop {
                        let mut line = String::new();
                        stream.read_line(&mut line).await.unwrap();
                        let line = line.trim_end();
                        if line.is_empty() {
                            break;
                        }
                        let (name, value) = line.split_once(':').unwrap();
                        match name.to_ascii_lowercase().as_str() {
                            "content-length" => content_length = value.trim().parse().unwrap(),
                            "content-type" => content_type = value.trim().to_string(),
                            _ => {}
                        }
                    }
                    assert_eq!(content_type, "application/dns-message");
                    let mut body = vec![0u8; content_length];
                    stream.read_exact(&mut body).await.unwrap();
                    let query = state.record(&body);
                    let bytes = answer(&query, ANSWER);
                    let head = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/dns-message\r\ncontent-length: {}\r\n\r\n",
                        bytes.len()
                    );
                    let inner = stream.get_mut();
                    inner.write_all(head.as_bytes()).await.unwrap();
                    inner.write_all(&bytes).await.unwrap();
                    inner.flush().await.unwrap();
                }
            });
        }
    });
    (addr, seen)
}

/// A plain UDP bootstrap server that says `dns.test` is 127.0.0.1.
async fn bootstrap_server() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let (len, peer) = socket.recv_from(&mut buf).await.unwrap();
            let query = Message::from_vec(&buf[..len]).unwrap();
            assert_eq!(query.queries[0].name().to_ascii(), "dns.test.");
            socket
                .send_to(&answer(&query, Ipv4Addr::LOCALHOST), peer)
                .await
                .unwrap();
        }
    });
    addr
}

fn upstreams(server: &str, bootstrap: Option<SocketAddr>, tls: &Tls) -> Upstreams {
    let config = UpstreamConfig {
        servers: vec![server.parse().unwrap()],
        bootstrap: bootstrap.map(UpstreamAddr::Udp).into_iter().collect(),
        timeout_ms: 2000,
    };
    Upstreams::with_tls_config(&config, tls.client.clone()).unwrap()
}

fn query(name: &str) -> Message {
    let mut query = Message::query();
    query.metadata.recursion_desired = true;
    query.add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
    query.set_edns(Edns::new());
    query
}

fn first_a(response: &Message) -> Ipv4Addr {
    match &response.answers[0].data {
        RData::A(a) => a.0,
        other => panic!("unexpected answer {other:?}"),
    }
}

#[tokio::test]
async fn dot_by_ip_reuses_connection_and_pads_queries() {
    let tls = tls(&[]);
    let (addr, seen) = dot_server(tls.acceptor.clone()).await;
    let upstreams = upstreams(&format!("tls://{addr}#dns.test"), None, &tls);

    for name in ["one.example.", "a-longer-name.two.example."] {
        let response = upstreams.resolve(&query(name)).await.unwrap();
        assert_eq!(first_a(&response), ANSWER);
    }
    assert_eq!(seen.connections.load(Ordering::SeqCst), 1);
    for len in seen.query_lengths.lock().unwrap().iter() {
        assert_eq!(len % 128, 0, "query of {len} bytes is not padded");
    }
}

#[tokio::test]
async fn dot_by_hostname_uses_bootstrap() {
    let tls = tls(&[]);
    let (addr, _) = dot_server(tls.acceptor.clone()).await;
    let bootstrap = bootstrap_server().await;
    let upstreams = upstreams(
        &format!("tls://dns.test:{}", addr.port()),
        Some(bootstrap),
        &tls,
    );

    let response = upstreams.resolve(&query("example.org.")).await.unwrap();
    assert_eq!(first_a(&response), ANSWER);
}

#[tokio::test]
async fn dot_rejects_wrong_certificate_name() {
    let tls = tls(&[]);
    let (addr, seen) = dot_server(tls.acceptor.clone()).await;
    let upstreams = upstreams(&format!("tls://{addr}#other.test"), None, &tls);

    assert!(upstreams.resolve(&query("example.org.")).await.is_err());
    assert_eq!(seen.connections.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn doh_posts_padded_queries_with_id_zero() {
    let tls = tls(&[b"http/1.1"]);
    let (addr, seen) = doh_server(tls.acceptor.clone()).await;
    let bootstrap = bootstrap_server().await;
    let upstreams = upstreams(
        &format!("https://dns.test:{}/dns-query", addr.port()),
        Some(bootstrap),
        &tls,
    );

    let original = query("example.net.");
    let response = upstreams.resolve(&original).await.unwrap();
    assert_eq!(first_a(&response), ANSWER);
    assert_eq!(*seen.query_ids.lock().unwrap(), vec![0]);
    assert_eq!(seen.query_lengths.lock().unwrap()[0] % 128, 0);

    // A second query reuses the pooled HTTP connection.
    upstreams.resolve(&query("example.com.")).await.unwrap();
    assert_eq!(seen.connections.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn dot_retries_when_a_fresh_connection_is_dropped() {
    let tls = tls(&[]);
    let (addr, seen) = dot_server_dropping(tls.acceptor.clone(), 1).await;
    let upstreams = upstreams(&format!("tls://{addr}#dns.test"), None, &tls);

    let response = upstreams.resolve(&query("example.org.")).await.unwrap();
    assert_eq!(first_a(&response), ANSWER);
    assert_eq!(seen.connections.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn dot_gives_up_after_one_retry() {
    let tls = tls(&[]);
    let (addr, seen) = dot_server_dropping(tls.acceptor.clone(), 2).await;
    let upstreams = upstreams(&format!("tls://{addr}#dns.test"), None, &tls);

    assert!(upstreams.resolve(&query("example.org.")).await.is_err());
    assert_eq!(seen.connections.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn doh_retries_when_the_connection_is_dropped() {
    let tls = tls(&[b"http/1.1"]);
    let (addr, seen) = doh_server_dropping(tls.acceptor.clone(), 1).await;
    let bootstrap = bootstrap_server().await;
    let upstreams = upstreams(
        &format!("https://dns.test:{}/dns-query", addr.port()),
        Some(bootstrap),
        &tls,
    );

    let response = upstreams.resolve(&query("example.net.")).await.unwrap();
    assert_eq!(first_a(&response), ANSWER);
    assert_eq!(seen.connections.load(Ordering::SeqCst), 2);
}
