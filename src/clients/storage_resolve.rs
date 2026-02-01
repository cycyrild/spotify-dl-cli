use prost::Message;
use tracing::instrument;

use crate::constants::STORAGE_RESOLVE_V2_ENDPOINT;
use crate::http_client::HttpClient;
use crate::proto::storage_resolve::StorageResolveResponse;

#[derive(Clone)]
pub struct StorageResolverClient {
    http: HttpClient,
}

impl StorageResolverClient {
    pub fn new(http: HttpClient) -> Self {
        Self { http }
    }

    #[instrument(skip(self))]
    pub fn resolve(&self, file_id: &[u8]) -> anyhow::Result<Vec<String>> {
        let url = format!("{}/{}", STORAGE_RESOLVE_V2_ENDPOINT, hex::encode(file_id));
        let resp = self.http.with_protobuf().get(&url)?;
        parse_response(&resp.bytes()?)
    }
}

fn parse_response(blob: &[u8]) -> anyhow::Result<Vec<String>> {
    let mut sr = StorageResolveResponse::default();
    sr.merge(blob)?;

    if sr.result != Some(storage_resolve_response::Result::Cdn as i32) {
        anyhow::bail!("storage-resolve failed: result={:?}", sr.result);
    }

    Ok(sr.cdnurl)
}

mod storage_resolve_response {
    pub use crate::proto::storage_resolve::storage_resolve_response::Result;
}
