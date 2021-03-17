use crate::error::{Result, ServerError};
use crate::Server;
use actix_web::{web, HttpResponse, Responder};
use anonify_ecall_types::cmd::*;
use anonify_eth_driver::traits::*;
use std::{sync::Arc, time};
use tracing::{error, info};

const DEFAULT_GAS: u64 = 5_000_000;

pub async fn handle_health_check() -> impl Responder {
    HttpResponse::Ok().finish()
}

pub async fn handle_join_group<S, W>(server: web::Data<Arc<Server<S, W>>>) -> Result<HttpResponse>
where
    S: Sender,
    W: Watcher,
{
    let sender_address = server
        .dispatcher
        .get_account(server.account_index, server.password.as_deref())
        .await
        .map_err(|e| ServerError::from(e))?;
    let tx_hash = server
        .dispatcher
        .join_group(sender_address, DEFAULT_GAS, JOIN_GROUP_CMD)
        .await
        .map_err(|e| ServerError::from(e))?;

    Ok(HttpResponse::Accepted()
        .json(state_runtime_node_api::join_group::post::Response { tx_hash }))
}

pub async fn handle_update_mrenclave<S, W>(
    server: web::Data<Arc<Server<S, W>>>,
) -> Result<HttpResponse>
where
    S: Sender,
    W: Watcher,
{
    let sender_address = server
        .dispatcher
        .get_account(server.account_index, server.password.as_deref())
        .await
        .map_err(|e| ServerError::from(e))?;
    let tx_hash = server
        .dispatcher
        .update_mrenclave(sender_address, DEFAULT_GAS, JOIN_GROUP_CMD)
        .await
        .map_err(|e| ServerError::from(e))?;

    Ok(HttpResponse::Accepted()
        .json(state_runtime_node_api::update_mrenclave::post::Response { tx_hash }))
}

pub async fn handle_send_command<S, W>(
    server: web::Data<Arc<Server<S, W>>>,
    req: web::Json<state_runtime_node_api::state::post::Request>,
) -> Result<HttpResponse>
where
    S: Sender,
    W: Watcher,
{
    let sender_address = server
        .dispatcher
        .get_account(server.account_index, server.password.as_deref())
        .await
        .map_err(|e| ServerError::from(e))?;

    let tx_hash = server
        .dispatcher
        .send_command(
            req.ciphertext.clone(),
            req.user_id,
            sender_address,
            DEFAULT_GAS,
            SEND_COMMAND_CMD,
        )
        .await
        .map_err(|e| ServerError::from(e))?;

    Ok(HttpResponse::Accepted().json(state_runtime_node_api::state::post::Response { tx_hash }))
}

pub async fn handle_key_rotation<S, W>(server: web::Data<Arc<Server<S, W>>>) -> Result<HttpResponse>
where
    S: Sender,
    W: Watcher,
{
    let sender_address = server
        .dispatcher
        .get_account(server.account_index, server.password.as_deref())
        .await
        .map_err(|e| ServerError::from(e))?;
    let tx_hash = server
        .dispatcher
        .handshake(sender_address, DEFAULT_GAS, SEND_HANDSHAKE_CMD)
        .await
        .map_err(|e| ServerError::from(e))?;

    Ok(HttpResponse::Accepted()
        .json(state_runtime_node_api::key_rotation::post::Response { tx_hash }))
}

/// Fetch events from blockchain nodes manually, and then get the state data from enclave.
pub async fn handle_get_state<S, W>(
    server: web::Data<Arc<Server<S, W>>>,
    req: web::Json<state_runtime_node_api::state::get::Request>,
) -> Result<HttpResponse>
where
    S: Sender,
    W: Watcher,
{
    server
        .dispatcher
        .fetch_events(FETCH_CIPHERTEXT_CMD, FETCH_HANDSHAKE_CMD)
        .await
        .map_err(|e| ServerError::from(e))?;

    let state = server
        .dispatcher
        .get_state(req.ciphertext.clone(), GET_STATE_CMD)
        .map_err(|e| ServerError::from(e))?;

    Ok(HttpResponse::Ok().json(state_runtime_node_api::state::get::Response { state }))
}

/// Fetch events from blockchain nodes manually, and then get the user counter from enclave.
pub async fn handle_get_user_counter<S, W>(
    server: web::Data<Arc<Server<S, W>>>,
    req: web::Json<state_runtime_node_api::user_counter::get::Request>,
) -> Result<HttpResponse>
where
    S: Sender,
    W: Watcher,
{
    server
        .dispatcher
        .fetch_events(FETCH_CIPHERTEXT_CMD, FETCH_HANDSHAKE_CMD)
        .await
        .map_err(|e| ServerError::from(e))?;

    let user_counter = server
        .dispatcher
        .get_user_counter(req.ciphertext.clone(), GET_USER_COUNTER_CMD)
        .map_err(|e| ServerError::from(e))?;

    Ok(HttpResponse::Ok()
        .json(state_runtime_node_api::user_counter::get::Response { user_counter }))
}

pub async fn handle_enclave_encryption_key<S, W>(
    server: web::Data<Arc<Server<S, W>>>,
) -> Result<HttpResponse>
where
    S: Sender,
    W: Watcher,
{
    let enclave_encryption_key = server
        .dispatcher
        .get_enclave_encryption_key(GET_ENCLAVE_ENCRYPTION_KEY_CMD)
        .map_err(|e| ServerError::from(e))?;

    Ok(HttpResponse::Ok().json(
        state_runtime_node_api::enclave_encryption_key::get::Response {
            enclave_encryption_key,
        },
    ))
}

pub async fn handle_start_sync_bc<S, W>(
    server: web::Data<Arc<Server<S, W>>>,
) -> Result<HttpResponse>
where
    S: Sender + Send + Sync + 'static,
    W: Watcher + Send + Sync + 'static,
{
    // it spawns a new OS thread, and hosts an event loop.
    actix_rt::Arbiter::new().exec_fn(move || {
        actix_rt::spawn(async move {
            loop {
                match server
                    .dispatcher
                    .fetch_events(FETCH_CIPHERTEXT_CMD, FETCH_HANDSHAKE_CMD)
                    .await
                {
                    Ok(updated_states) => info!("State updated: {:?}", updated_states),
                    Err(err) => error!("event fetched error: {:?}", err),
                };
                actix_rt::time::delay_for(time::Duration::from_millis(server.sync_time)).await;
            }
        });
    });

    Ok(HttpResponse::Ok().finish())
}

pub async fn handle_register_notification<S, W>(
    server: web::Data<Arc<Server<S, W>>>,
    req: web::Json<state_runtime_node_api::register_notification::post::Request>,
) -> Result<HttpResponse>
where
    S: Sender,
    W: Watcher,
{
    server
        .dispatcher
        .register_notification(req.ciphertext.clone(), REGISTER_NOTIFICATION_CMD)
        .map_err(|e| ServerError::from(e))?;

    Ok(HttpResponse::Ok().finish())
}

pub async fn handle_register_report<S, W>(
    server: web::Data<Arc<Server<S, W>>>,
) -> Result<HttpResponse>
where
    S: Sender,
    W: Watcher,
{
    let sender_address = server
        .dispatcher
        .get_account(server.account_index, server.password.as_deref())
        .await
        .map_err(|e| ServerError::from(e))?;
    let tx_hash = server
        .dispatcher
        .register_report(sender_address, DEFAULT_GAS, SEND_REGISTER_REPORT_CMD)
        .await
        .map_err(|e| ServerError::from(e))?;

    Ok(HttpResponse::Accepted()
        .json(state_runtime_node_api::register_report::post::Response { tx_hash }))
}

#[cfg(feature = "backup-enable")]
pub async fn handle_all_backup_to<S, W>(
    server: web::Data<Arc<Server<S, W>>>,
) -> Result<HttpResponse>
where
    S: Sender,
    W: Watcher,
{
    server
        .dispatcher
        .all_backup_to(BACKUP_PATH_SECRET_ALL_CMD)?;

    Ok(HttpResponse::Ok().finish())
}

#[cfg(feature = "backup-enable")]
pub async fn handle_all_backup_from<S, W>(
    server: web::Data<Arc<Server<S, W>>>,
) -> Result<HttpResponse>
where
    S: Sender,
    W: Watcher,
{
    server
        .dispatcher
        .all_backup_from(RECOVER_PATH_SECRET_ALL_CMD)?;

    Ok(HttpResponse::Ok().finish())
}
