use actix_web::{web, App, HttpServer};
use actix_web_opentelemetry::RequestTracing;
use frame_host::EnclaveDir;
use state_runtime_node_server::{handlers::*, Server};
use std::{env, io, sync::Arc};
use tracing_subscriber::{prelude::*, Registry};

#[actix_web::main]
async fn main() -> io::Result<()> {
    let (tracer, _uninstall) = opentelemetry_jaeger::new_pipeline()
        .with_service_name("erc20")
        .install()
        .unwrap();

    let log_level = env::var("RUST_LOG").unwrap_or_else(|_| "INFO".to_string());

    Registry::default()
        .with(tracing_subscriber::EnvFilter::new(log_level))
        .with(tracing_subscriber::fmt::layer())
        .with(tracing_opentelemetry::layer().with_tracer(tracer))
        .init();

    let my_node_url = env::var("MY_NODE_URL").expect("MY_NODE_URL is not set.");
    let num_workers: usize = env::var("NUM_WORKERS")
        .unwrap_or_else(|_| "16".to_string())
        .parse()
        .expect("Failed to parse NUM_WORKERS");
    let is_debug: bool = env::var("IS_DEBUG")
        .unwrap_or_else(|_| "true".to_string())
        .parse()
        .expect("Failed to parse IS_DEBUG");

    // Enclave must be initialized in main function.
    let enclave = EnclaveDir::new()
        .init_enclave(is_debug)
        .expect("Failed to initialize enclave.");
    let eid = enclave.geteid();
    let server = Server::new(eid).await.run().await;
    let server = Arc::new(server);

    HttpServer::new(move || {
        App::new()
            .wrap(RequestTracing::new())
            .app_data(server.clone())
            .route("/api/v1/health", web::get().to(handle_health_check))
            .route("/api/v1/state", web::post().to(handle_send_command))
            .route("/api/v1/state", web::get().to(handle_get_state))
            .route(
                "/api/v1/user_counter",
                web::get().to(handle_get_user_counter),
            )
            .route("/api/v1/key_rotation", web::post().to(handle_key_rotation))
            .route(
                "/api/v1/register_notification",
                web::post().to(handle_register_notification),
            )
            .route(
                "/api/v1/enclave_encryption_key",
                web::get().to(handle_enclave_encryption_key),
            )
            .route(
                "/api/v1/register_report",
                web::post().to(handle_register_report),
            )
    })
    .bind(my_node_url)?
    .workers(num_workers)
    .run()
    .await
}
