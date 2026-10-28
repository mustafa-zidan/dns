//! DNS-over-HTTPS (RFC 8484).

use std::sync::Arc;

use anyhow::{Result, bail};
use hickory_proto::op::Message;
use rustls::ClientConfig;
use tracing::debug;

use super::bootstrap::{Bootstrap, BootstrapResolver};
use super::{closed_early, encode_padded, is_response_to};

const DNS_MESSAGE: &str = "application/dns-message";

pub struct HttpsUpstream {
    url: reqwest::Url,
    client: reqwest::Client,
}

impl HttpsUpstream {
    pub fn new(
        url: reqwest::Url,
        tls_config: &ClientConfig,
        bootstrap: Arc<Bootstrap>,
    ) -> Result<Self> {
        let mut tls_config = tls_config.clone();
        tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        // No User-Agent and no cookies: nothing that identifies this client
        // beyond what HTTPS itself needs. Proxy environment variables are
        // ignored so queries go straight to the resolver, addressed through
        // the bootstrap servers.
        let client = reqwest::Client::builder()
            .tls_backend_preconfigured(tls_config)
            .dns_resolver(Arc::new(BootstrapResolver(bootstrap)))
            .https_only(true)
            .no_proxy()
            .build()?;
        Ok(Self { url, client })
    }

    pub async fn exchange(&self, query: &Message) -> Result<Message> {
        // RFC 8484 asks clients to use ID 0, which keeps answers HTTP-cacheable.
        let mut query = query.clone();
        query.metadata.id = 0;
        let body = encode_padded(&query)?;

        let bytes = match self.post(body.clone()).await {
            Err(e) if closed_early(&e) => {
                debug!(error = %e, "DoH upstream closed the connection early, retrying once");
                self.post(body).await
            }
            result => result,
        }?;
        let answer = Message::from_vec(&bytes)?;
        if !is_response_to(&answer, &query) {
            bail!("upstream answer does not match the query");
        }
        Ok(answer)
    }

    async fn post(&self, body: Vec<u8>) -> Result<Vec<u8>> {
        let response = self
            .client
            .post(self.url.clone())
            .header(reqwest::header::CONTENT_TYPE, DNS_MESSAGE)
            .header(reqwest::header::ACCEPT, DNS_MESSAGE)
            .body(body)
            .send()
            .await?;
        if !response.status().is_success() {
            bail!("HTTP {}", response.status());
        }
        Ok(response.bytes().await?.to_vec())
    }
}
