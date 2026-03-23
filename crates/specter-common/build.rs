fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_files = &[
        "proto/specter/v1/sessions.proto",
        "proto/specter/v1/tasks.proto",
        "proto/specter/v1/listeners.proto",
        "proto/specter/v1/operators.proto",
        "proto/specter/v1/profiles.proto",
        "proto/specter/v1/certificates.proto",
        "proto/specter/v1/webhooks.proto",
        "proto/specter/v1/campaigns.proto",
        "proto/specter/v1/modules.proto",
        "proto/specter/v1/builder.proto",
        "proto/specter/v1/azure.proto",
        "proto/specter/v1/collaboration.proto",
        "proto/specter/v1/reports.proto",
        "proto/specter/v1/specter_service.proto",
    ];

    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(proto_files, &["proto"])?;

    for proto in proto_files {
        println!("cargo:rerun-if-changed={proto}");
    }

    Ok(())
}
