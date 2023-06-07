#!/bin/bash

# Copyright (c) 2018-2022 The MobileCoin Foundation

set -eo pipefail

data="/fog-data"

if [[ -n "${MC_LEDGER_DB_URL}" ]]
then
    ### CBB: these should use ENV vars for configuration.
    #   Need to fix .internal-ci/helm/mc-core-common-config/templates/mobilecoind-supervisord-mobilecoind-configmap.yaml

    echo "MC_LEDGER_DB_URL set, restoring ${data}/ledger/data.mdb from backup"
    if [[ -f "${data}/ledger/data.mdb" ]]
    then
        echo "Found existing ledger database, skipping download"
    else
        echo "Downloading ledger data.mdb"
        mkdir -p /tmp/ledger
        curl -L "${MC_LEDGER_DB_URL}" -o "/tmp/ledger/data.mdb"
        mkdir -p "${data}/ledger"
        mv /tmp/ledger/data.mdb ${data}/ledger/data.mdb
    fi
fi

if [[ -n "${MC_WATCHER_DB_URL}" ]]
then
    echo "MC_WATCHER_DB_URL set, restoring ${data}/watcher/data.mdb from backup"
    if [[ -f "${data}/watcher/data.mdb" ]]
    then
        echo "Found existing watcher database, skipping download"
    else
        echo "Downloading watcher data.mdb"
        mkdir -p /tmp/watcher
        curl -L "${MC_WATCHER_DB_URL}" -o "/tmp/watcher/data.mdb"
        mkdir -p "${data}/watcher"
        mv /tmp/watcher/data.mdb ${data}/watcher/data.mdb
    fi
fi

exec "$@"