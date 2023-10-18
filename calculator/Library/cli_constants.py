# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
# Copyright (c) 2021-2021 Zkrypto Inc.
# SPDX-License-Identifier: LGPL-3.0+


"""
Constants and defaults specific to the CLI interface.
"""

ETH_RPC_ENDPOINT_DEFAULTS = {
    "klaytn": "https://api.baobab.klaytn.net:8651",
    "ganache": "http://localhost:8545",
    # "ganache" : "https://testnet.chainz.biz",
    "autonity-helloworld": "http://localhost:8541",
}

ROLLUP_URL_DEFAULT = "http://localhost:8000/rollup"
POST_HEADERS_JSON = {
    'content-type': 'application/json',
}

ETH_NETWORK_FILE_DEFAULT = "eth-network"
ETH_NETWORK_DEFAULT = "ganache"
KLAYTN_NETWORK_DEFAULT = "klaytn"
PROVER_SERVER_ENDPOINT_DEFAULT = "localhost:50051"
BALANCE_PROVER_SERVER_ENDPOINT_DEFAULT = "localhost:50052"

ZKLAY_SECRET_ADDRESS_FILE_DEFAULT = "zklay-address.priv"
ZKLAY_PUBLIC_ADDRESS_FILE_DEFAULT = "zklay-address.pub"

ZKLAY_AUDIT_SECRET_ADDRESS_FILE_DEFAULT = "audit-address.priv"
ZKLAY_AUDIT_PUBLIC_ADDRESS_FILE_DEFAULT = "audit-address.pub"

INSTANCE_FILE_DEFAULT = "zklay-instance"
TOKEN_INSTANCE_FILE_DEFAULT = "token-instance"

INSTANCE_FILE = "zklay_instance.json"
WITNESS_FILE = "zklay_witness.json"

ETH_ADDRESS_DEFAULT = "eth-address"
ETH_PRIVATE_KEY_FILE_DEFAULT = "eth-private-key"

PROVER_CONFIGURATION_FILE_DEFAULT = "prover-config.cache"
BALANCE_PROVER_CONFIGURATION_FILE_DEFAULT = "balance-prover-config.cache"

WALLET_DIR_DEFAULT = "./wallet"
WALLET_USERNAME = "zklay"

ACC_DATA_FILE: str = "acc.dat"

CONFIG_FILE: str = "config.cache"

HASH_TYPE: list = [
    "SHA256",
    "MiMC7",
    "Poseidon"
]

TEST_VK_FILE_NAME: str = "test_vk.json"

TEST_TX_PATH: str = "test_transactions/txs"

CLIENT_CONFIG_FILE = "client_config"