use anyhow::Context;
use tracing::info;

use crate::clients::{playplay::PlayPlayClient, storage_resolve::StorageResolverClient};
use crate::http_client::HttpClient;
use crate::ogg_parser::reconstruct_ogg_from_chunks;
use crate::playplay_keygen::PlayPlayKeygen;
use crate::proto::track::audio_file::Format as AudioFormat;
use crate::proto::track::Track;

use clap::ValueEnum;

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum Quality {
    #[value(name = "ogg-96")]
    Ogg96,
    #[value(name = "ogg-160")]
    Ogg160,
    #[value(name = "ogg-320")]
    Ogg320,
}

#[derive(Clone, Copy)]
pub struct AudioFormatChoice {
    pub format: AudioFormat,
}

pub fn audio_format(quality: Quality) -> AudioFormatChoice {
    match quality {
        Quality::Ogg96 => AudioFormatChoice {
            format: AudioFormat::OggVorbis96,
        },
        Quality::Ogg160 => AudioFormatChoice {
            format: AudioFormat::OggVorbis160,
        },
        Quality::Ogg320 => AudioFormatChoice {
            format: AudioFormat::OggVorbis320,
        },
    }
}

const CHUNK_SIZE: usize = 0x10000;

pub fn download_track(
    http: &HttpClient,
    track: &Track,
    resolver: &StorageResolverClient,
    playplay: &PlayPlayClient,
    keygen: &PlayPlayKeygen,
    audio_format: AudioFormatChoice,
) -> anyhow::Result<()> {
    let file_id = track
        .file
        .iter()
        .find(|f| f.format == Some(audio_format.format as i32))
        .and_then(|f| f.file_id.clone())
        .context("audio format unavailable")?;

    let obfuscated_key = playplay.get_obfuscated_key(&file_id)?;
    let mut kg = keygen.clone();
    kg.configure(&file_id[..16], &obfuscated_key)?;

    let urls = resolver.resolve(&file_id)?;
    let url = urls
        .get(0)
        .cloned()
        .context("No URL returned by resolver")?;

    let output_path = format!("{}.ogg", hex::encode(&file_id));
    info!("Downloading: {}", output_path);

    let mut file = std::fs::File::create(&output_path)?;
    let mut resp = http.stream(&url)?;
    let body = resp.bytes()?;
    let decrypted = kg.decrypt_stream(std::iter::once(body.to_vec()));
    for page in reconstruct_ogg_from_chunks(decrypted) {
        std::io::Write::write_all(&mut file, &page)?;
    }

    Ok(())
}
