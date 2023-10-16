# Copyright (c) 2021-2021 Zkrypto Inc.
#
# SPDX-License-Identifier: LGPL-3.0+

from zklay.core.context import ClientConfig
from zklay.core.zklay_encryption import PublicKeyEncryptionSystem
from zklay.core.zklay_snark import Proof, VerificationKey
import zklay.core.utils as core_utils
import zklay.cli.utils as cli_utils
import zklay.core.contracts as contracts
import zklay.core.constants as constants
from zklay.core.zklay_client import ZklayClient
from zklay.cli.constants import TEST_VK_FILE_NAME
from zklay.core.utils import EtherValue
from zklay.core.contracts import send_contract_call
from typing import List, Any, Optional
from zklay.cli.debugger import print_value, print_msg_box
import os
import time
import functools
import json


AUDIT_PRIV_FILE = "audit-address.priv"
AUDIT_PUB_FILE = "audit-address.pub"

PRIV_FILE = "zklay-address.priv"
PUB_FILE = "zklay-address.pub"

CIRCUIT_NAME = "ZKlay"

DEFAULT_VALUE = 1000000
ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"


def print_balances_token(
        token: Any, deployer: str, auditor: str, alice: str, bob: str) -> None:
    print("TOKEN BALANCES:")
    print(f"  Depolyer  : {token.functions.balanceOf(deployer).call()}")
    print(f"  Auditor   : {token.functions.balanceOf(auditor).call()}")
    print(f"  Alice     : {token.functions.balanceOf(alice).call()}")
    print(f"  Bob       : {token.functions.balanceOf(bob).call()}")


def path_wrapper(cur_pwd):
    def wrapper(func):
        @functools.wraps(func)
        def decorator(*args, **kwargs):
            start_time = time.time()
            msg = f"[INFO    ] :: START , Call :    {func.__name__:37s}  Time : [ {0:03f} s]"
            print_msg_box(msg,  width=91, title=func.__name__)
            res = func(*args, **kwargs)
            msg = f"[INFO    ] :: END   , Call :    {func.__name__:37s}  Time : [ {round(time.time() - start_time, 4):3f} s]"
            print_msg_box(msg, width=91, title=func.__name__)
            os.chdir(cur_pwd)
            return res
        return decorator
    return wrapper


def mkdir_user(user_name, eth_address):
    try:
        os.system(f"mkdir {user_name}")  # bob
        os.chdir(f"./{user_name}")
        os.system("cp ../deployer/zklay-instance .")
        os.system("cp ../auditor/audit-address.pub .")
        os.system("cp ../deployer/" + CIRCUIT_NAME + "_CRS_pk.dat .")
        os.system("cp ../deployer/" + CIRCUIT_NAME + "_CRS_vk.dat .")
        os.system(f"echo {eth_address} > eth-address")

    except Exception as e:
        print(f"[ERROR :: mkdir_user] {e}")


def mkdir_auditor(auditor_name, eth_address):
    try:
        os.system(f"mkdir {auditor_name}")  # bob
        os.chdir(f"./{auditor_name}")
        os.system("cp ../deployer/zklay-instance .")
        os.system(f"echo {eth_address} > eth-address")

    except Exception as e:
        print(f"[ERROR :: mkdir_auditor] {e}")


def token_approve(
        web3: Any,
        token: Any,
        sender: str,
        receiver: str,
        tx_value: Optional[EtherValue] = EtherValue(0),
        amount: Optional[int] = DEFAULT_VALUE,
        receiver_eth_priv_key: Optional[bytes] = None,
        gas: Optional[int] = DEFAULT_VALUE):

    approve_call = token.functions.approve(sender, amount)

    tx_hash = send_contract_call(
        web3,
        approve_call,
        receiver,
        receiver_eth_priv_key,
        tx_value,
        gas)

    return tx_hash.hex()


@path_wrapper(os.getcwd())
def transfer(
        zklay_client: Any,
        zklay_desc: Any,
        circuit: str,
        auditor_pub: Any,
        sender_pub: Any,
        sender_priv: Any,
        receiver_pub: Any,
        pocket: core_utils.Pocket,
        client_ctx: Any,
        sender_address: Any,
        receiver_address: Any,
        path: str,
        sender_eth_private_key: Optional[bytes] = None):

    os.chdir(f"{path}")

    zklay_wallet = cli_utils.open_zklay_wallet(
        zklay_client.zklay_instance, sender_priv, client_ctx)

    trans_param, _ = zklay_client.create_trans_args( #이게 proof만들고,,proof만들려면 input들을 만들어야하고, 그리고 proving하는 과정이 여기
        circuit_name=circuit,
        zklay_wallet=zklay_wallet,
        auditor_pub=auditor_pub,
        sender_pub=sender_pub,
        sender_priv=sender_priv,
        receiver_pub=receiver_pub,
        pocket=pocket,
        toEoA=receiver_address
    )

    token_address = zklay_desc.token.address
    token_abi = zklay_desc.token.abi

    token = zklay_client.web3.eth.contract(
        address=token_address,
        abi=token_abi,
    )

    zklay = zklay_desc.mixer.address

    token_approve(
        web3=zklay_client.web3,
        token=token,
        sender=zklay,
        receiver=sender_address,
        receiver_eth_priv_key=sender_eth_private_key
    )

    tx_hash = zklay_client.anontransfer(
        trans_param=trans_param,
        sender_eth_address=sender_address,
        sender_eth_private_key=sender_eth_private_key,
        tx_value=pocket.v_in
    )

    print_value(tx_hash, name="tx_hash", func_name="anotransfer")

    return trans_param


@path_wrapper(os.getcwd())
def sync(
        client_ctx: Any,
        zklay_client: Any,
        receiver_priv: Any,
        receiver_path: Any
):

    os.chdir(f"./{receiver_path}")
    zklay_wallet = cli_utils.open_zklay_wallet(
        zklay_client.zklay_instance, receiver_priv, client_ctx)
    cli_utils.do_sync_trans(zklay_client.web3, zklay_wallet,
                            receiver_priv)


def all_sync(
        client_ctx: Any,
        zklay_client: Any,
        receiver_path_list: List[Any]):
    cur_pwd = os.getcwd()

    for data in receiver_path_list:
        os.chdir(f"./{data[2]}")
        zklay_wallet = cli_utils.open_zklay_wallet(
            zklay_client.zklay_instance, data[1], client_ctx)
        cli_utils.do_sync_trans(
            zklay_client.web3, zklay_wallet)
        os.chdir(cur_pwd)


def test_deploy(
    web3: Any,
    client_ctx: ClientConfig,
    deployer_eth_address: str,
    deployer_eth_private_key: Optional[bytes],
    token_address: Optional[str] = None,
    deploy_gas: Optional[int] = None,
):

    contracts_dir = core_utils.get_contracts_dir()
    smart_contract_name = "Groth16AltBN128Mixer"  # TO DO
    mixer_src = os.path.join(contracts_dir, smart_contract_name + ".sol")

    vk_file_path = constants.CLIENT_PATH + \
        "/TEST/default_deployer/" + TEST_VK_FILE_NAME
    vk = VerificationKey.from_json_file(vk_file_path)

    vk_contract_parameter = VerificationKey.verification_key_to_contract_parameters(
        vk)

    constructor_parameters: List[Any] = [
        int(client_ctx.depth),
        token_address or ZERO_ADDRESS,     # token
        vk_contract_parameter,  # vk
        cli_utils.get_hash_num(client_ctx.hash)
    ]

    mixer_description = contracts.InstanceDescription.deploy(
        web3,
        mixer_src,
        smart_contract_name,
        deployer_eth_address,
        deployer_eth_private_key,
        deploy_gas,
        compiler_flags={},
        args=constructor_parameters)
    zklay_instance = mixer_description.instantiate(web3)
    client = ZklayClient(web3, zklay_instance, client_ctx)

    return client, mixer_description


def read_test_tx(file_path: str) -> List[Any]:
    with open(file_path, 'r') as f:
        tx_data = json.load(f)

    proof = Proof.from_json(tx_data["proof"])
    proof_contract_params = Proof.proof_to_contract_parameters(
        proof)

    trans_call_desc = tx_data["trans_call_desc"]
    trans_output = trans_call_desc["TransOutput"]

    addr = trans_output["addr"]
    k_b = trans_call_desc["k_b"]
    k_u = trans_call_desc["k_u"]
    v_out = trans_call_desc["pv_"]
    v_in = trans_call_desc["pv"]
    c_3 = trans_call_desc["CT"]
    c_0 = trans_call_desc["G_r"]
    c_1 = trans_call_desc["K_u"]
    c_2 = trans_call_desc["K_a"]

    print([
        proof_contract_params,
        trans_call_desc["rt"],
        trans_call_desc["sn"],
        [addr, k_b, k_u],
        trans_call_desc["cm_"],
        trans_call_desc["cout"],
        [v_in, v_out],
        [c_0, c_1, c_2] + c_3,
        trans_call_desc["eoaReceiver"]
    ])
    return [
        proof_contract_params,
        trans_call_desc["rt"],
        trans_call_desc["sn"],
        [addr, k_b, k_u],
        trans_call_desc["cm_"],
        trans_call_desc["cout"],
        [v_in, v_out],
        [c_0, c_1, c_2] + c_3,
        trans_call_desc["eoaReceiver"]
    ]
