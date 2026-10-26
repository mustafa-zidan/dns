//! Resolves the hostnames of encrypted upstreams through plain DNS servers,
//! so the server never depends on the operating system's resolver (which may
//! well be this server).

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, anyhow};
use hickory_proto::op::{Message, Query};
use hickory_proto::rr::{Name, RData, RecordType};
use tokio::time::timeout;

use super::{UpstreamAddr, plain};

pub struct Bootstrap {
    servers: Vec<UpstreamAddr>,
    timeout: Duration,
}

impl Bootstrap {
    pub fn new(servers: Vec<UpstreamAddr>, timeout: Duration) -> Self {
        Self { servers, timeout }
    }

    /// Looks up the A and AAAA records of `host`, trying each bootstrap server in turn.
    pub async fn lookup(&self, host: &str) -> Result<Vec<IpAddr>> {
        let name = Name::from_ascii(host)?;
        let mut last_err = anyhow!("no bootstrap servers configured");
        for server in &self.servers {
            let (v4, v6) = tokio::join!(
                self.query(server, &name, RecordType::A),
                self.query(server, &name, RecordType::AAAA),
            );
            let mut ips = Vec::new();
            for result in [v4, v6] {
                match result {
                    Ok(found) => ips.extend(found),
                    Err(e) => last_err = e,
                }
            }
            if !ips.is_empty() {
                return Ok(ips);
            }
        }
        Err(last_err.context(format!("bootstrap lookup of {host} failed")))
    }

    async fn query(
        &self,
        server: &UpstreamAddr,
        name: &Name,
        record_type: RecordType,
    ) -> Result<Vec<IpAddr>> {
        let mut query = Message::query();
        query.metadata.recursion_desired = true;
        query.add_query(Query::query(name.clone(), record_type));
        let response = timeout(self.timeout, plain::exchange(server, &query))
            .await
            .map_err(|_| anyhow!("timed out querying {server}"))??;
        Ok(response
            .answers
            .iter()
            .filter_map(|r| match &r.data {
                RData::A(a) => Some(IpAddr::V4(a.0)),
                RData::AAAA(aaaa) => Some(IpAddr::V6(aaaa.0)),
                _ => None,
            })
            .collect())
    }
}

/// Lets reqwest resolve DoH hostnames through the bootstrap servers.
pub struct BootstrapResolver(pub Arc<Bootstrap>);

impl reqwest::dns::Resolve for BootstrapResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let bootstrap = Arc::clone(&self.0);
        Box::pin(async move {
            let ips = bootstrap.lookup(name.as_str()).await?;
            // Port 0 is replaced with the URL's port by reqwest.
            let addrs: reqwest::dns::Addrs =
                Box::new(ips.into_iter().map(|ip| SocketAddr::new(ip, 0)));
            Ok(addrs)
        })
    }
}
