use actix_web::{web, App, HttpServer};
use frame_host::EnclaveDir;
use key_vault_node_server::{handlers::*, Server};
use std::{env, io, sync::Arc};

#[actix_web::main]
async fn main() -> io::Result<()> {
    tracing_subscriber::fmt::init();
    let my_node_url = env::var("MY_NODE_URL").expect("MY_NODE_URL is not set.");
    let num_workers: usize = env::var("NUM_WORKERS")
        .unwrap_or_else(|_| "16".to_string())
        .parse()
        .expect("Failed to parse NUM_WORKERS");
    let is_debug: bool = env::var("IS_DEBUG")
        .unwrap_or_else(|_| "true".to_string())
        .parse()
        .expect("Failed to parse IS_DEBUG");

    let enclave = EnclaveDir::new()
        .init_enclave(is_debug)
        .expect("Failed to initialize enclave.");
    let eid = enclave.geteid();
    let server = Arc::new(Server::new(eid).run().await);

    HttpServer::new(move || {
        App::new()
            .app_data(server.clone())
            .route("/api/v1/health", web::get().to(handle_health_check))
    })
    .bind(my_node_url)?
    .workers(num_workers)
    .run()
    .await
}
