mod clients;
mod constants;
mod downloader;
mod http_client;
mod ogg_parser;
mod playplay_keygen;
mod proto;

use anyhow::Context;
use clap::{ArgAction, Parser, ValueEnum};
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "playplay", about = "Spotify OGG downloader")]
struct Args {
    #[arg(long, required = true, help = "Spotify bearer token")]
    token: String,
    #[arg(long, required = true, num_args = 1.., help = "List of Spotify track URIs")]
    tracks: Vec<String>,
    #[arg(
        long,
        value_enum,
        default_value = "ogg-160",
        help = "Audio quality (default: ogg-160)"
    )]
    quality: downloader::Quality,
    #[arg(long, default_value = "bin.exe", help = "Path to the PlayPlay executable")]
    exe_path: String,
    #[arg(
        long,
        default_value = "info",
        value_parser = ["debug", "info", "warn", "error"],
        help = "Log level"
    )]
    log_level: String,
    #[arg(long, action = ArgAction::SetTrue, help = "Disable TLS verification")]
    insecure: bool,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let filter = EnvFilter::builder()
        .with_default_directive(args.log_level.parse()?)
        .from_env_lossy();
    tracing_subscriber::fmt().with_env_filter(filter).init();

    let audio_format = downloader::audio_format(args.quality);

    let http = http_client::HttpClient::new(&args.token, !args.insecure)?;
    let keygen = playplay_keygen::PlayPlayKeygen::new(&args.exe_path)
        .context("initialize keygen from PE")?;

    let metadata = clients::metadata::ExtendedMetadataClient::new(http.clone());
    let resolver = clients::storage_resolve::StorageResolverClient::new(http.clone());
    let playplay = clients::playplay::PlayPlayClient::new(http.clone(), keygen.playplay_token());

    let tracks = metadata
        .fetch_tracks(&args.tracks)
        .context("fetch tracks")?;

    for (uri, track) in tracks {
        tracing::info!("Track: {}", track.name.as_deref().unwrap_or("unknown"));
        tracing::info!("GID: {:x?}", track.gid);
        tracing::info!("Duration: {}", track.duration);

        downloader::download_track(
            &http,
            &track,
            &resolver,
            &playplay,
            &keygen,
            audio_format,
        )
        .with_context(|| format!("download {}", uri))?;
    }

    Ok(())
}
