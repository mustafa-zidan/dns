//! Queries real public resolvers over every transport. Needs internet access,
//! so it is ignored by default; CI runs it with `cargo test -- --ignored`.

use hickory_proto::op::{Edns, Message, Query, ResponseCode};
use hickory_proto::rr::{Name, RecordType};

use dns::config::UpstreamConfig;
use dns::upstream::Upstreams;

#[tokio::test]
#[ignore = "needs internet access"]
async fn resolves_through_public_resolvers() {
    for server in [
        "udp://1.1.1.1",
        "tcp://9.9.9.9",
        "tls://1.1.1.1#cloudflare-dns.com",
        "tls://dns.quad9.net",
        "https://cloudflare-dns.com/dns-query",
        "https://dns.quad9.net/dns-query",
    ] {
        let config = UpstreamConfig {
            servers: vec![server.parse().unwrap()],
            ..UpstreamConfig::default()
        };
        let upstreams = Upstreams::new(&config).unwrap();
        let mut query = Message::query();
        query.metadata.recursion_desired = true;
        query.add_query(Query::query(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
        ));
        query.set_edns(Edns::new());

        let response = upstreams
            .resolve(&query)
            .await
            .unwrap_or_else(|e| panic!("{server}: {e:#}"));
        assert_eq!(response.response_code, ResponseCode::NoError, "{server}");
        assert!(!response.answers.is_empty(), "{server}: no answers");
    }
}
