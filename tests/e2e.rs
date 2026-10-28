//! End-to-end tests: a real server on loopback in front of a fake upstream.

use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use hushdns::blocklist::Blocklist;
use hushdns::cache::Cache;
use hushdns::clients::Clients;
use hushdns::config::{BlockingConfig, CacheConfig, Config, StatsConfig, UpstreamConfig};
use hushdns::handler::Handler;
use hushdns::server;
use hushdns::stats::Stats;
use hushdns::upstream::{UpstreamAddr, Upstreams};

const ANSWER: A = A(std::net::Ipv4Addr::new(192, 0, 2, 7));

fn answer_for(request: &Message, truncated: bool) -> Vec<u8> {
    let mut response = Message::response(request.id, OpCode::Query);
    response.metadata.recursion_available = true;
    response.queries = request.queries.clone();
    if truncated {
        response.metadata.truncation = true;
    } else {
        response.add_answer(Record::from_rdata(
            request.queries[0].name().clone(),
            300,
            RData::A(ANSWER),
        ));
    }
    response.to_vec().unwrap()
}

/// A fake upstream that answers every A query with 192.0.2.7 and counts queries.
/// With `truncate_udp`, UDP answers come back truncated so the client must use TCP.
async fn fake_upstream(truncate_udp: bool) -> (SocketAddr, Arc<AtomicUsize>) {
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = udp.local_addr().unwrap();
    let tcp = TcpListener::bind(addr).await.unwrap();
    let count = Arc::new(AtomicUsize::new(0));

    let udp_count = Arc::clone(&count);
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let (len, peer) = udp.recv_from(&mut buf).await.unwrap();
            udp_count.fetch_add(1, Ordering::SeqCst);
            let request = Message::from_vec(&buf[..len]).unwrap();
            udp.send_to(&answer_for(&request, truncate_udp), peer)
                .await
                .unwrap();
        }
    });

    let tcp_count = Arc::clone(&count);
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = tcp.accept().await.unwrap();
            tcp_count.fetch_add(1, Ordering::SeqCst);
            let len = stream.read_u16().await.unwrap() as usize;
            let mut buf = vec![0u8; len];
            stream.read_exact(&mut buf).await.unwrap();
            let request = Message::from_vec(&buf).unwrap();
            let bytes = answer_for(&request, false);
            stream.write_u16(bytes.len() as u16).await.unwrap();
            stream.write_all(&bytes).await.unwrap();
        }
    });

    (addr, count)
}

async fn start_server(upstream: SocketAddr) -> (SocketAddr, SocketAddr) {
    let blocking = BlockingConfig {
        denylist: vec!["ads.example.com".into()],
        allowlist: vec!["ok.ads.example.com".into()],
        ..BlockingConfig::default()
    };
    let handler = Arc::new(Handler::new(
        Arc::new(Blocklist::new(blocking.clone()).unwrap()),
        &blocking,
        Arc::new(Cache::new(CacheConfig::default())),
        Upstreams::new(&UpstreamConfig {
            servers: vec![UpstreamAddr::Udp(upstream)],
            ..UpstreamConfig::default()
        })
        .unwrap(),
        Arc::new(Stats::new(&StatsConfig::default())),
    ));
    let any: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let udp = server::bind_udp(any, Arc::clone(&handler)).await.unwrap();
    let tcp = server::bind_tcp(any, handler, Duration::from_secs(5))
        .await
        .unwrap();
    (udp, tcp)
}

fn query(id: u16, name: &str) -> Vec<u8> {
    let mut msg = Message::new(id, MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = true;
    msg.add_query(Query::query(Name::from_str(name).unwrap(), RecordType::A));
    msg.to_vec().unwrap()
}

async fn ask_udp(server: SocketAddr, id: u16, name: &str) -> Message {
    ask_udp_from("127.0.0.1", server, id, name).await
}

async fn ask_udp_from(source: &str, server: SocketAddr, id: u16, name: &str) -> Message {
    let socket = UdpSocket::bind((source, 0)).await.unwrap();
    socket.send_to(&query(id, name), server).await.unwrap();
    let mut buf = vec![0u8; 4096];
    let (len, _) = tokio::time::timeout(Duration::from_secs(5), socket.recv_from(&mut buf))
        .await
        .expect("no answer")
        .unwrap();
    Message::from_vec(&buf[..len]).unwrap()
}

#[tokio::test]
async fn resolves_through_upstream_and_caches() {
    let (upstream, count) = fake_upstream(false).await;
    let (udp, _) = start_server(upstream).await;

    let first = ask_udp(udp, 1, "www.example.org.").await;
    assert_eq!(first.id, 1);
    assert_eq!(first.response_code, ResponseCode::NoError);
    assert_eq!(first.answers[0].data, RData::A(ANSWER));
    assert_eq!(count.load(Ordering::SeqCst), 1);

    // Same name with different case: served from cache, upstream not asked again.
    let second = ask_udp(udp, 2, "WWW.Example.org.").await;
    assert_eq!(second.id, 2);
    assert_eq!(second.answers[0].data, RData::A(ANSWER));
    assert_eq!(count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn blocks_listed_domains_but_not_allowlisted_ones() {
    let (upstream, count) = fake_upstream(false).await;
    let (udp, _) = start_server(upstream).await;

    let blocked = ask_udp(udp, 3, "banner.ads.example.com.").await;
    assert_eq!(blocked.response_code, ResponseCode::NXDomain);
    assert_eq!(count.load(Ordering::SeqCst), 0);

    let allowed = ask_udp(udp, 4, "ok.ads.example.com.").await;
    assert_eq!(allowed.response_code, ResponseCode::NoError);
    assert_eq!(count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn falls_back_to_tcp_when_upstream_truncates() {
    let (upstream, count) = fake_upstream(true).await;
    let (udp, _) = start_server(upstream).await;

    let response = ask_udp(udp, 5, "big.example.org.").await;
    assert_eq!(response.answers[0].data, RData::A(ANSWER));
    // One truncated UDP answer, then one TCP connection.
    assert_eq!(count.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn serves_tcp_clients() {
    let (upstream, _) = fake_upstream(false).await;
    let (_, tcp) = start_server(upstream).await;

    let mut stream = TcpStream::connect(tcp).await.unwrap();
    for id in [10u16, 11] {
        let bytes = query(id, "tcp.example.org.");
        stream.write_u16(bytes.len() as u16).await.unwrap();
        stream.write_all(&bytes).await.unwrap();
        let len = stream.read_u16().await.unwrap() as usize;
        let mut buf = vec![0u8; len];
        stream.read_exact(&mut buf).await.unwrap();
        let response = Message::from_vec(&buf).unwrap();
        assert_eq!(response.id, id);
        assert_eq!(response.answers[0].data, RData::A(ANSWER));
    }
}

#[tokio::test]
async fn answers_pipelined_tcp_queries_as_they_are_ready() {
    // An upstream that never answers, so forwarded queries hang until they time out.
    let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (_, tcp) = start_server(silent.local_addr().unwrap()).await;

    let mut stream = TcpStream::connect(tcp).await.unwrap();
    for (id, name) in [
        (20u16, "slow.example.org."),
        (21, "banner.ads.example.com."),
    ] {
        let bytes = query(id, name);
        stream.write_u16(bytes.len() as u16).await.unwrap();
        stream.write_all(&bytes).await.unwrap();
    }
    // The blocked name is answered first, without waiting for the slow one.
    let len = tokio::time::timeout(Duration::from_secs(1), stream.read_u16())
        .await
        .expect("blocked query held up behind the slow one")
        .unwrap() as usize;
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await.unwrap();
    let response = Message::from_vec(&buf).unwrap();
    assert_eq!(response.id, 21);
    assert_eq!(response.response_code, ResponseCode::NXDomain);
}

#[tokio::test]
async fn retries_tcp_upstream_that_drops_the_connection() {
    // Reads the first query and hangs up; answers on the next connection.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let connections = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&connections);
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let first = seen.fetch_add(1, Ordering::SeqCst) == 0;
            let len = stream.read_u16().await.unwrap();
            let mut buf = vec![0u8; len as usize];
            stream.read_exact(&mut buf).await.unwrap();
            if first {
                continue;
            }
            let bytes = answer_for(&Message::from_vec(&buf).unwrap(), false);
            stream.write_u16(bytes.len() as u16).await.unwrap();
            stream.write_all(&bytes).await.unwrap();
        }
    });

    let upstreams = Upstreams::new(&UpstreamConfig {
        servers: vec![UpstreamAddr::Tcp(addr)],
        ..UpstreamConfig::default()
    })
    .unwrap();
    let mut request = Message::new(9, MessageType::Query, OpCode::Query);
    request.add_query(Query::query(
        Name::from_str("example.org.").unwrap(),
        RecordType::A,
    ));
    let response = upstreams.resolve(&request).await.unwrap();
    assert_eq!(response.answers[0].data, RData::A(ANSWER));
    assert_eq!(connections.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn applies_per_client_rules_by_source_address() {
    let (upstream, _) = fake_upstream(false).await;
    let config = Config::parse(
        r#"
        [blocking]
        denylist = ["ads.example.com"]

        [[clients]]
        name = "kids"
        addresses = ["127.0.0.2"]
        denylist = ["video.example"]

        [[clients]]
        name = "unfiltered"
        addresses = ["127.0.0.3/32"]
        blocklists = false
        "#,
    )
    .unwrap();
    let handler = Handler::new(
        Arc::new(
            Blocklist::new(config.blocking.clone())
                .unwrap()
                .with_clients(Arc::new(Clients::new(&config.clients, None).unwrap())),
        ),
        &config.blocking,
        Arc::new(Cache::new(CacheConfig::default())),
        Upstreams::new(&UpstreamConfig {
            servers: vec![UpstreamAddr::Udp(upstream)],
            ..UpstreamConfig::default()
        })
        .unwrap(),
        Arc::new(Stats::new(&StatsConfig::default())),
    );
    let server = server::bind_udp("127.0.0.1:0".parse().unwrap(), Arc::new(handler))
        .await
        .unwrap();

    let code =
        |source, name| async move { ask_udp_from(source, server, 1, name).await.response_code };
    // Everyone else: only the shared rules.
    assert_eq!(
        code("127.0.0.1", "video.example.").await,
        ResponseCode::NoError
    );
    assert_eq!(
        code("127.0.0.1", "ads.example.com.").await,
        ResponseCode::NXDomain
    );
    // Kids: their own denylist on top of the shared rules.
    assert_eq!(
        code("127.0.0.2", "video.example.").await,
        ResponseCode::NXDomain
    );
    assert_eq!(
        code("127.0.0.2", "ads.example.com.").await,
        ResponseCode::NXDomain
    );
    // Unfiltered: the shared rules are skipped.
    assert_eq!(
        code("127.0.0.3", "ads.example.com.").await,
        ResponseCode::NoError
    );
}
