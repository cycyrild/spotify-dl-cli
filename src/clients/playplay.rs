use chrono::Utc;
use prost::Message;
use tracing::instrument;

use crate::constants::PLAYPLAY_ENDPOINT;
use crate::http_client::HttpClient;
use crate::proto::playplay::{
    play_play_license_request::ContentType, play_play_license_request::Interactivity,
    PlayPlayLicenseRequest, PlayPlayLicenseResponse,
};

#[derive(Clone)]
pub struct PlayPlayClient {
    http: HttpClient,
    token: Vec<u8>,
}

impl PlayPlayClient {
    pub fn new(http: HttpClient, playplay_token: &[u8]) -> Self {
        Self {
            http,
            token: playplay_token.to_vec(),
        }
    }

    #[instrument(skip(self))]
    pub fn get_obfuscated_key(&self, file_id: &[u8]) -> anyhow::Result<Vec<u8>> {
        let payload = build_license_request(&self.token);
        let url = format!("{}/{}", PLAYPLAY_ENDPOINT, hex::encode(file_id));

        let resp = self.http.with_protobuf().post(&url, &payload)?;
        parse_license_response(&resp.bytes()?)
    }
}

fn build_license_request(token: &[u8]) -> Vec<u8> {
    let mut req = PlayPlayLicenseRequest::default();
    req.version = Some(3);
    req.token = Some(token.to_vec());
    req.interactivity = Some(Interactivity::Interactive as i32);
    req.content_type = Some(ContentType::AudioTrack as i32);
    req.timestamp = Some(Utc::now().timestamp());

    let mut buf = Vec::new();
    req.encode(&mut buf).expect("encode license request");
    buf
}

fn parse_license_response(blob: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut res = PlayPlayLicenseResponse::default();
    res.merge(blob)?;

    if let Some(key) = res.obfuscated_key {
        Ok(key)
    } else {
        anyhow::bail!("playplay: empty obfuscated_key")
    }
}
