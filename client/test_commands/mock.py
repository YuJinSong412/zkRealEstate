#!/usr/bin/env python3

# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
# Copyright (c) 2021-2021 Zkrypto Inc
# SPDX-License-Identifier: LGPL-3.0+

from genericpath import exists
from zklay.cli.constants import ETH_NETWORK_DEFAULT, KLAYTN_NETWORK_DEFAULT
from zklay.core.utils import get_contracts_dir, open_web3
from zklay.core.contracts import compile_files
from os.path import join
from typing import Dict, List, Tuple, Optional, Any
from web3.middleware import geth_poa_middleware
import json,os

# Web3 HTTP provider
TEST_PROVER_SERVER_ENDPOINT: str = "localhost:50051"
TEST_NOTE_DIR: str = "_test_notes"
jwt ="eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJwZXJtaXNzaW9ucyI6WyJldGg6KiIsIm5ldDoqIiwid2ViMzoqIl0sImV4cCI6MTY2MzI5MjQ1Mn0.JzKEQ5JLwDYq8MEAHs7dyVshQMEVqKknv3MXd9bdDNZM_PY88KNMMiP0vYaM9TQxsVRf52IFOzfKfLjf0BpHV7obnR_c8lvHcMUK5_yk6LlMRr-Sa3pzn9aNz5s2bZ8RRa2F7urRXVZ0yNPme1YD2y7Vqh9H_TYqW5hXoYXyedJ4S9BNVuY8beJaob-ZlO8UYjPi330i6G7Redcf4Mk-Yby80GMWVFzLBdIjdm2Z5DPSEm8CLM3jhn436aDsMES6KPENAfYHqTJydSRj9lwLmyIS_q07gEbXXG7YfGB2_6Td-1u2pYY0y0bfooVU-J3lZp-v8KHHZm5TzcTv9wT4hg"
WEB3_ENDPOINT_DEFAULTS = {
    "klaytn" : "https://api.baobab.klaytn.net:8651",
    "ganache": "http://localhost:8545",
    "besu" : "https://testnet.chainz.biz"
}


def open_test_web3(env) -> Tuple[Any, Any]: 
    web3 = open_web3(WEB3_ENDPOINT_DEFAULTS[env], insecure = False)

    web3.middleware_stack.inject(geth_poa_middleware, layer=0)

    return web3, web3.eth  # pylint: disable=no-member # type: ignore

def create_user(web3 : Any, pwd : str) -> Tuple[Any,Any] :
    try : 
        if os.path.isfile(pwd + ".key") :
            with open(pwd + ".key") as user : 
                data = json.loads(user.read())
                address = data["address"]
                privateKey = data["privateKey"]
                return address, privateKey
        else :  
            user = web3.eth.account.create(pwd)
            with open(pwd + ".key", "w") as pub_addr_f:
                test = {
                    "address" : str(user.address),
                    "privateKey" : user.privateKey.hex()
                }
                pub_addr_f.write(json.dumps(test))
            return user.address, user.privateKey.hex()
    except :
        print("write zklay audit_address_public")


def get_dummy_merkle_path(length: int) -> List[str]:
    mk_path = []
    # Arbitrary sha256 digest used to build the dummy merkle path
    dummy_node = \
        "6461f753bfe21ba2219ced74875b8dbd8c114c3c79d7e41306dd82118de1895b"
    for _ in range(length):
        mk_path.append(dummy_node)
    return mk_path


def deploy_contract(
        eth: Any,
        deployer_address: str,
        contract_name: str,
        constructor_args: Optional[Dict[str, Any]] = None) -> Tuple[Any, Any]:
    contracts_dir = get_contracts_dir()
    sol_path = join(contracts_dir, contract_name + ".sol")
    compiled_sol = compile_files([sol_path])
    interface = compiled_sol[sol_path + ":" + contract_name]
    contract_abi = interface['abi']
    contract = eth.contract(abi=contract_abi, bytecode=interface['bin'])
    deploy_tx = contract.constructor(**constructor_args)
    deploy_tx_hash = deploy_tx.transact({'from': deployer_address})
    tx_receipt = eth.waitForTransactionReceipt(deploy_tx_hash, 1000)
    contract_address = tx_receipt['contractAddress']
    contract_instance = eth.contract(
        address=contract_address,
        abi=contract_abi)
    return interface, contract_instance
