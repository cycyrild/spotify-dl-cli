use std::time::Duration;

use anyhow::Context;
use reqwest::blocking::{Client, Response};
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, AUTHORIZATION, CONTENT_TYPE, USER_AGENT};

use crate::constants::USER_AGENT as UA;

#[derive(Clone)]
pub struct HttpClient {
    client: Client,
    token: String,
    verify_tls: bool,
}

impl HttpClient {
    pub fn new(token: &str, verify_tls: bool) -> anyhow::Result<Self> {
        let mut headers = HeaderMap::new();
        headers.insert(USER_AGENT, HeaderValue::from_static(UA));

        if !token.is_empty() {
            let value = format!("Bearer {token}");
            headers.insert(
                AUTHORIZATION,
                HeaderValue::from_str(&value).context("invalid auth header")?,
            );
        }

        let mut builder = Client::builder()
            .default_headers(headers)
            .timeout(Duration::from_secs(30));

        if !verify_tls {
            builder = builder.danger_accept_invalid_certs(true);
        }

        let client = builder.build().context("build client")?;
        Ok(Self {
            client,
            token: token.to_string(),
            verify_tls,
        })
    }

    pub fn with_protobuf(&self) -> Self {
        let mut headers = HeaderMap::new();
        headers.insert(USER_AGENT, HeaderValue::from_static(UA));
        if !self.token.is_empty() {
            let value = format!("Bearer {}", self.token);
            headers.insert(
                AUTHORIZATION,
                HeaderValue::from_str(&value).expect("auth header"),
            );
        }
        headers.insert(ACCEPT, HeaderValue::from_static("application/protobuf"));
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/protobuf"));

        let mut builder = Client::builder()
            .default_headers(headers)
            .timeout(Duration::from_secs(30));
        if !self.verify_tls {
            builder = builder.danger_accept_invalid_certs(true);
        }
        let client = builder.build().expect("build protobuf client");
        Self {
            client,
            token: self.token.clone(),
            verify_tls: self.verify_tls,
        }
    }

    pub fn get(&self, url: &str) -> anyhow::Result<Response> {
        let resp = self.client.get(url).send().context("http get")?;
        resp.error_for_status_ref().context("status")?;
        Ok(resp)
    }

    pub fn post(&self, url: &str, body: &[u8]) -> anyhow::Result<Response> {
        let resp = self
            .client
            .post(url)
            .body(body.to_vec())
            .send()
            .context("http post")?;
        resp.error_for_status_ref().context("status")?;
        Ok(resp)
    }

    pub fn stream(&self, url: &str) -> anyhow::Result<reqwest::blocking::Response> {
        let resp = self.client.get(url).send().context("http stream")?;
        resp.error_for_status_ref().context("status")?;
        Ok(resp)
    }
}
