// Copyright (c) 2018-2022 The MobileCoin Foundation

use std::{env, str::FromStr, sync::Arc};

use clap::Parser;
use grpcio::ChannelBuilder;
use mc_common::logger::log;
use mc_fog_api::ledger_grpc::KeyImageStoreApiClient;
use mc_fog_ledger_enclave::{LedgerSgxEnclave, ENCLAVE_FILE};
use mc_fog_ledger_server::{KeyImageRouterServer, LedgerRouterConfig};
use mc_fog_uri::{KeyImageStoreScheme, KeyImageStoreUri};

use mc_util_grpc::ConnectionUriGrpcioChannel;
use mc_util_uri::UriScheme;

fn main() {
    mc_common::setup_panic_handler();
    let config = LedgerRouterConfig::parse();
    let (logger, _global_logger_guard) =
        mc_common::logger::create_app_logger(mc_common::logger::o!());

    let enclave_path = env::current_exe()
        .expect("Could not get the path of our executable")
        .with_file_name(ENCLAVE_FILE);
    log::info!(
        logger,
        "enclave path {}, responder ID {}",
        enclave_path.to_str().unwrap(),
        &config.client_responder_id
    );
    let enclave = LedgerSgxEnclave::new(
        enclave_path,
        &config.client_responder_id,
        config.omap_capacity,
        logger.clone(),
    );

    let mut ledger_store_grpc_clients: Vec<KeyImageStoreApiClient> = Vec::new();
    let grpc_env = Arc::new(
        grpcio::EnvBuilder::new()
            .name_prefix("Main-RPC".to_string())
            .build(),
    );
    for i in 0..50 {
        let shard_uri_string = format!(
            "{}://node{}.test.mobilecoin.com:3225",
            KeyImageStoreScheme::SCHEME_INSECURE,
            i
        );
        let shard_uri = KeyImageStoreUri::from_str(&shard_uri_string).unwrap();
        let ledger_store_grpc_client = KeyImageStoreApiClient::new(
            ChannelBuilder::default_channel_builder(grpc_env.clone())
                .connect_to_uri(&shard_uri, &logger),
        );
        ledger_store_grpc_clients.push(ledger_store_grpc_client);
    }

    let mut router_server =
        KeyImageRouterServer::new(config, enclave, ledger_store_grpc_clients, logger);
    router_server.start();

    loop {
        std::thread::sleep(std::time::Duration::from_millis(1000));
    }
}
