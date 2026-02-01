fn main() {
    let proto_files = [
        "proto/playplay.proto",
        "proto/storage-resolve.proto",
        "proto/track.proto",
    ];

    let includes = ["proto", "proto/google"];

    let mut config = prost_build::Config::new();
    std::env::set_var(
        "PROTOC",
        protoc_bin_vendored::protoc_bin_path().expect("protoc path"),
    );
    config
        .protoc_arg("--experimental_allow_proto3_optional")
        .out_dir("src/proto")
        .compile_well_known_types()
        .type_attribute(".", "#[derive(serde::Deserialize, serde::Serialize)]");

    config
        .compile_protos(&proto_files, &includes)
        .expect("failed to compile protos");
}
