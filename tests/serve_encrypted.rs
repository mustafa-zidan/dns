//! DNS-over-TLS and DNS-over-HTTPS served to clients, with a self-signed
//! certificate for `dns.test` written to temporary files.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hickory_proto::op::{Edns, Message, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use rustls::pki_types::{CertificateDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use dns::blocklist::Blocklist;
use dns::cache::Cache;
use dns::certs::CertStore;
use dns::config::{BlockingConfig, CacheConfig, StatsConfig, UpstreamConfig};
use dns::handler::Handler;
use dns::stats::Stats;
use dns::upstream::{UpstreamAddr, Upstreams};
use dns::{doh, padding, server};

const ANSWER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 53);
const IDLE: Duration = Duration::from_secs(5);

/// A self-signed certificate for `dns.test`, written to its own directory.
struct Cert {
    dir: PathBuf,
    der: CertificateDer<'static>,
}

impl Cert {
    fn cert_file(&self) -> PathBuf {
        self.dir.join("fullchain.pem")
    }

    fn key_file(&self) -> PathBuf {
        self.dir.join("privkey.pem")
    }

    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "dns-serve-encrypted-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let cert = Self {
            dir,
            der: CertificateDer::from(Vec::new()),
        };
        cert.renew()
    }

    /// Writes a new certificate and key over the old files, with a later
    /// modification time so a reload notices them.
    fn renew(mut self) -> Self {
        let key = rcgen::generate_simple_self_signed(vec!["dns.test".to_string()]).unwrap();
        std::fs::write(self.cert_file(), key.cert.pem()).unwrap();
        std::fs::write(self.key_file(), key.signing_key.serialize_pem()).unwrap();
        let later = SystemTime::now() + Duration::from_secs(60 * (1 + self.der.len() as u64 % 7));
        for path in [self.cert_file(), self.key_file()] {
            let file = std::fs::File::options().write(true).open(path).unwrap();
            file.set_modified(later).unwrap();
        }
        self.der = key.cert.der().clone();
        self
    }

    fn client_config(&self, alpn: &[&[u8]]) -> rustls::ClientConfig {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(self.der.clone()).unwrap();
        let mut config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
        config
    }
}

impl Drop for Cert {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A plain UDP upstream that answers every A query with [`ANSWER`].
async fn fake_upstream() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let (len, peer) = socket.recv_from(&mut buf).await.unwrap();
            let query = Message::from_vec(&buf[..len]).unwrap();
            let mut response = Message::response(query.id, OpCode::Query);
            response.queries = query.queries.clone();
            response.add_answer(Record::from_rdata(
                query.queries[0].name().clone(),
                300,
                RData::A(A(ANSWER)),
            ));
            socket
                .send_to(&response.to_vec().unwrap(), peer)
                .await
                .unwrap();
        }
    });
    addr
}

async fn handler() -> Arc<Handler> {
    let blocking = BlockingConfig {
        denylist: vec!["ads.example.com".into()],
        ..BlockingConfig::default()
    };
    Arc::new(Handler::new(
        Arc::new(Blocklist::new(blocking.clone()).unwrap()),
        &blocking,
        Arc::new(Cache::new(CacheConfig::default())),
        Upstreams::new(&UpstreamConfig {
            servers: vec![UpstreamAddr::Udp(fake_upstream().await)],
            ..UpstreamConfig::default()
        })
        .unwrap(),
        Arc::new(Stats::new(&StatsConfig::default())),
    ))
}

async fn start_dot(store: &Arc<CertStore>) -> SocketAddr {
    let tls = TlsAcceptor::from(store.server_config(&[server::DOT_ALPN]));
    server::bind_dot("127.0.0.1:0".parse().unwrap(), tls, handler().await, IDLE)
        .await
        .unwrap()
}

async fn start_doh(store: &Arc<CertStore>) -> SocketAddr {
    let tls = TlsAcceptor::from(store.server_config(doh::ALPN));
    doh::bind(
        "127.0.0.1:0".parse().unwrap(),
        "/dns-query",
        tls,
        handler().await,
        IDLE,
    )
    .await
    .unwrap()
}

fn query(name: &str) -> Message {
    let mut query = Message::query();
    query.metadata.id = 4242;
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

/// Opens a DoT connection that trusts `cert` and sends one framed query.
async fn ask_dot(addr: SocketAddr, cert: &Cert, query: &[u8]) -> std::io::Result<Vec<u8>> {
    let connector = TlsConnector::from(Arc::new(cert.client_config(&[server::DOT_ALPN])));
    let tcp = TcpStream::connect(addr).await?;
    let name = ServerName::try_from("dns.test").unwrap();
    let mut stream = connector.connect(name, tcp).await?;
    assert_eq!(stream.get_ref().1.alpn_protocol(), Some(server::DOT_ALPN));
    stream.write_u16(query.len() as u16).await?;
    stream.write_all(query).await?;
    stream.flush().await?;
    let len = stream.read_u16().await?;
    let mut buf = vec![0u8; len as usize];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

fn doh_client(cert: &Cert, addr: SocketAddr) -> reqwest::Client {
    reqwest::Client::builder()
        .tls_backend_preconfigured(cert.client_config(doh::ALPN))
        .resolve("dns.test", addr)
        .no_proxy()
        .build()
        .unwrap()
}

#[tokio::test]
async fn dot_answers_and_blocks() {
    let cert = Cert::new();
    let store = CertStore::load(&cert.cert_file(), &cert.key_file()).unwrap();
    let addr = start_dot(&store).await;

    // The project's own DoT client, pointed at the server.
    let config = UpstreamConfig {
        servers: vec![format!("tls://{addr}#dns.test").parse().unwrap()],
        ..UpstreamConfig::default()
    };
    let client = Upstreams::with_tls_config(&config, cert.client_config(&[])).unwrap();
    let response = client.resolve(&query("example.org.")).await.unwrap();
    assert_eq!(first_a(&response), ANSWER);
    let blocked = client.resolve(&query("x.ads.example.com.")).await.unwrap();
    assert_eq!(blocked.response_code, ResponseCode::NXDomain);
}

#[tokio::test]
async fn dot_pads_responses_only_for_padded_queries() {
    let cert = Cert::new();
    let store = CertStore::load(&cert.cert_file(), &cert.key_file()).unwrap();
    let addr = start_dot(&store).await;

    let padded = padding::encode_padded(&query("example.org."), padding::QUERY_BLOCK).unwrap();
    let response = ask_dot(addr, &cert, &padded).await.unwrap();
    assert_eq!(
        response.len() % padding::RESPONSE_BLOCK,
        0,
        "{}",
        response.len()
    );
    assert_eq!(first_a(&Message::from_vec(&response).unwrap()), ANSWER);

    let plain = query("example.org.").to_vec().unwrap();
    let response = ask_dot(addr, &cert, &plain).await.unwrap();
    assert_ne!(response.len() % padding::RESPONSE_BLOCK, 0);
}

#[tokio::test]
async fn doh_answers_get_and_post_over_http2() {
    let cert = Cert::new();
    let store = CertStore::load(&cert.cert_file(), &cert.key_file()).unwrap();
    let addr = start_doh(&store).await;
    let client = doh_client(&cert, addr);
    let url = format!("https://dns.test:{}/dns-query", addr.port());

    // RFC 8484 clients send ID 0 so answers stay HTTP-cacheable.
    let mut request = query("example.org.");
    request.metadata.id = 0;
    let bytes = request.to_vec().unwrap();

    let get = client
        .get(format!("{url}?dns={}", URL_SAFE_NO_PAD.encode(&bytes)))
        .header("accept", "application/dns-message")
        .send()
        .await
        .unwrap();
    assert_eq!(get.status(), 200);
    assert_eq!(get.version(), reqwest::Version::HTTP_2);
    assert_eq!(get.headers()["content-type"], "application/dns-message");
    assert_eq!(get.headers()["cache-control"], "max-age=300");
    let answer = Message::from_vec(&get.bytes().await.unwrap()).unwrap();
    assert_eq!(answer.id, 0);
    assert_eq!(first_a(&answer), ANSWER);

    let post = client
        .post(&url)
        .header("content-type", "application/dns-message")
        .body(query("ads.example.com.").to_vec().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(post.status(), 200);
    let answer = Message::from_vec(&post.bytes().await.unwrap()).unwrap();
    assert_eq!(answer.response_code, ResponseCode::NXDomain);
}

#[tokio::test]
async fn doh_rejects_bad_requests() {
    let cert = Cert::new();
    let store = CertStore::load(&cert.cert_file(), &cert.key_file()).unwrap();
    let addr = start_doh(&store).await;
    let client = doh_client(&cert, addr);
    let url = format!("https://dns.test:{}/dns-query", addr.port());

    let wrong_type = client
        .post(&url)
        .header("content-type", "text/plain")
        .body("hello")
        .send()
        .await
        .unwrap();
    assert_eq!(wrong_type.status(), 415);

    let not_base64 = client.get(format!("{url}?dns=***")).send().await.unwrap();
    assert_eq!(not_base64.status(), 400);

    let not_dns = client
        .get(format!("{url}?dns={}", URL_SAFE_NO_PAD.encode(b"x")))
        .send()
        .await
        .unwrap();
    assert_eq!(not_dns.status(), 400);

    let elsewhere = client
        .get(format!("https://dns.test:{}/", addr.port()))
        .send()
        .await
        .unwrap();
    assert_eq!(elsewhere.status(), 404);
}

#[tokio::test]
async fn reloads_a_renewed_certificate() {
    let cert = Cert::new();
    let store = CertStore::load(&cert.cert_file(), &cert.key_file()).unwrap();
    let addr = start_dot(&store).await;
    let bytes = query("example.org.").to_vec().unwrap();
    assert!(!store.reload_if_changed().unwrap(), "nothing changed yet");

    let old = Cert {
        dir: cert.dir.clone(),
        der: cert.der.clone(),
    };
    let cert = cert.renew();
    assert!(store.reload_if_changed().unwrap());
    ask_dot(addr, &cert, &bytes).await.unwrap();
    // A client that only trusts the old certificate is now refused.
    assert!(ask_dot(addr, &old, &bytes).await.is_err());
    std::mem::forget(old);
}

#[tokio::test]
async fn keeps_the_current_certificate_when_the_new_one_is_broken() {
    let cert = Cert::new();
    let store = CertStore::load(&cert.cert_file(), &cert.key_file()).unwrap();
    let addr = start_dot(&store).await;

    std::fs::write(cert.key_file(), "not a key").unwrap();
    let later = SystemTime::now() + Duration::from_secs(600);
    std::fs::File::options()
        .write(true)
        .open(cert.key_file())
        .unwrap()
        .set_modified(later)
        .unwrap();
    assert!(store.reload_if_changed().is_err());
    let bytes = query("example.org.").to_vec().unwrap();
    ask_dot(addr, &cert, &bytes).await.unwrap();
}
