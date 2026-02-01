pub mod playplay {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/proto/spotify.playplay.proto.rs"));
}
pub mod storage_resolve {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/proto/spotify.download.proto.rs"
    ));
}
pub mod track {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/proto/spotify.extendedmetadata.rs"
    ));
}
pub mod google {
    pub mod protobuf {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/proto/google.protobuf.rs"
        ));
    }
}
