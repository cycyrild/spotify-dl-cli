use std::collections::HashMap;

use prost::Message;
use tracing::instrument;

use crate::constants::EXTENDED_METADATA_ENDPOINT;
use crate::http_client::HttpClient;
use crate::proto::track::{
    BatchedEntityRequest, BatchedExtensionResponse, BatchedEntityRequestHeader, EntityRequest,
    ExtensionKind, ExtensionQuery, Track,
};

#[derive(Clone)]
pub struct ExtendedMetadataClient {
    http: HttpClient,
}

impl ExtendedMetadataClient {
    pub fn new(http: HttpClient) -> Self {
        Self { http }
    }

    #[instrument(skip(self, uris))]
    pub fn fetch_tracks(&self, uris: &[String]) -> anyhow::Result<HashMap<String, Track>> {
        let payload = build_tracks_request(uris);
        let resp = self
            .http
            .with_protobuf()
            .post(EXTENDED_METADATA_ENDPOINT, &payload)?;
        parse_tracks_response(&resp.bytes()?)
    }
}

fn build_tracks_request(uris: &[String]) -> Vec<u8> {
    let mut request = BatchedEntityRequest::default();
    request.header = Some(BatchedEntityRequestHeader {
        country: String::new(),
        catalogue: String::new(),
        task_id: uuid::Uuid::new_v4().as_bytes().to_vec(),
    });

    let query = ExtensionQuery {
        extension_kind: ExtensionKind::TrackV4.into(),
        ..Default::default()
    };

    for uri in uris {
        request.entity_request.push(EntityRequest {
            entity_uri: uri.clone(),
            query: vec![query.clone()],
        });
    }

    let mut buf = Vec::new();
    request.encode(&mut buf).expect("encode request");
    buf
}

fn parse_tracks_response(blob: &[u8]) -> anyhow::Result<HashMap<String, Track>> {
    let mut response = BatchedExtensionResponse::default();
    response.merge(blob)?;

    let mut tracks = HashMap::new();

    for array in response.extended_metadata.into_iter() {
        if array.extension_kind != ExtensionKind::TrackV4.into() {
            continue;
        }
        for entity in array.extension_data {
            if let Some(any) = entity.extension_data {
                let mut track = Track::default();
                track.merge(any.value.as_ref())?;
                tracks.insert(entity.entity_uri, track);
            }
        }
    }

    Ok(tracks)
}
