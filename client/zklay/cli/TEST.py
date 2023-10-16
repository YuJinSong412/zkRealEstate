# Copyright (c) 2021-2021 Zkrypto Inc.
#
# SPDX-License-Identifier: LGPL-3.0+
from click import command, pass_context, Context
import zklay.core.utils as core_utils
import zklay.cli.utils as cli_utils
from zklay.core.zklay_client import ZklayClient
from zklay.core.utils import EtherValue, Pocket
from zklay.core.zklay_audit_address import ZklayAuditAddress, ZklayAuditAddressPub
from zklay.core.zklay_address import ZklayAddress
from zklay.cli.constants import INSTANCE_FILE_DEFAULT
import test_commands.mock as mock
from test_commands.deploy_test_token import deploy_token, mint_token
from typing import Any, Optional, Tuple
from zklay.cli.debugger import print_wrapper, print_value, print_msg_box
from zklay.cli.scenario import mkdir_user, mkdir_auditor, transfer, all_sync
import os
import shutil
import sys
import time

AUDIT_PRIV_FILE = "audit-address.priv"
AUDIT_PUB_FILE = "audit-address.pub"

PRIV_FILE = "zklay-address.priv"
PUB_FILE = "zklay-address.pub"

CIRCUIT = "ZKlay"

GANACHE = "ganache"
KLAYTN = "klaytn"
BESU = "besu"

DEFAULT_VALUE = 100000
DEPLOY_TOKEN_GAS = 8000000
DEFAULT_GAS_VALUE = 20000000


def print_balances(     #이더 value 확인
        web3: Any, deployer: str, auditor: str, alice: str, bob: str) -> None:
    print("BALANCES:")
    print(f"  zklay     : {web3.eth.getBalance(deployer)}")
    print(f"  Auditor   : {web3.eth.getBalance(auditor)}")
    print(f"  Alice     : {web3.eth.getBalance(alice)}")
    print(f"  Bob       : {web3.eth.getBalance(bob)}")


def print_balances_token(       #토큰 value 확인
        token: Any, deployer: str, auditor: str, alice: str, bob: str) -> None:
    print("TOKEN BALANCES:")
    print(f"  zklay     : {token.functions.balanceOf(deployer).call()}")
    print(f"  Auditor   : {token.functions.balanceOf(auditor).call()}")
    print(f"  Alice     : {token.functions.balanceOf(alice).call()}")
    print(f"  Bob       : {token.functions.balanceOf(bob).call()}")
    print(f"\nTotal     : {token.functions.totalSupply().call()}")


def gen_address(zklay_client: ZklayClient,      #User의 address 생성? 
                eth_address: str,
                user_eth_private_key: Optional[bytes] = None) -> Any:
    try:
        if os.path.exists(PUB_FILE):
            raise Exception(f"Pub File {PUB_FILE} exists")

        if os.path.exists(PRIV_FILE):
            raise Exception((f"Priv File {PRIV_FILE} exists"))
    except Exception as err:
        print(err)
        sys.exit()

    zklay_address = ZklayAddress.generate_keypair(zklay_client.client_ctx) #User key 생성

    cli_utils.write_zklay_address_public(zklay_address.upk, PUB_FILE)       #.upk
    print(f"\nPublic ZklayAddress written to {PUB_FILE}")

    cli_utils.write_zklay_address_secret(zklay_address.usk, PRIV_FILE)      #.usk
    print(f"Secret ZklayAddress written to {PRIV_FILE}\n")

    addr = core_utils.int256_to_bytes(zklay_address.upk.addr)   #upk에서 addr

    tx_hash = zklay_client.registerUser(        #registerUser 함수를 호출 -> 키 생성했으니 user정보를 블록체인에 올림
        addr=addr,
        user_eth_address=eth_address,
        user_eth_private_key=user_eth_private_key,
        tx_value=EtherValue(0))
    print_value(tx_hash, name="tx_hash", func_name="gen_address")

    return zklay_address


def clear_user_dirs(users: list[str]) -> None:  #user 삭제
    for user in users:
        if os.path.isdir(user):
            shutil.rmtree(user)


@command()
@print_wrapper(0)
@pass_context
def TEST(ctx: Context) -> None:     #실행 

    client_ctx = ctx.obj
    cur_pwd = os.getcwd()

    clear_user_dirs(["alice", "bob", "deployer", "auditor"])    #user 초기화

    web3, eth = mock.open_test_web3(client_ctx.env) #블록체인과 통신할 수 있는 web3, eth 라이브러리 인스턴스화 .,,,,,, ganache url 해서 이 블록체인을 사용한다.의 의미...이 블록체인만 특정한 것

    def get_address_ganache(eth: Any, idx: int) -> Tuple[str, None]:    #ganache에서,,,각 addresss 확인
        return eth.accounts[idx], None

    if client_ctx.env == GANACHE: #이렇게 하려면 ganache랑 연결해야되는 부분 필요하지 않남. 그건 어디? open_test_web3
        deployer_eth_address, deployer_eth_priv_key = get_address_ganache(  #EOA, EOA의 private key, addr_{user}-> ENA의 주소느낌....., 안에 담겨있는 값은 주소 입력하면 값이 암호화되어있는거고......................
            eth, 0)
        auditor_eth_address, auditor_eth_priv_key = get_address_ganache(eth, 1) #ganache에서 보면 address랑 key 부분
        alice_eth_address, alice_eth_priv_key = get_address_ganache(eth, 2)
        bob_eth_address, bob_eth_priv_key = get_address_ganache(eth, 3)
    elif client_ctx.env == KLAYTN:
        deployer_eth_address, deployer_eth_priv_key = mock.create_user(
            web3, "deployer")
        auditor_eth_address, auditor_eth_priv_key = mock.create_user(
            web3, "auditor")
        alice_eth_address, alice_eth_priv_key = mock.create_user(web3, "alice")
        bob_eth_address, bob_eth_priv_key = mock.create_user(web3, "bob")
    elif client_ctx.env == BESU:
        deployer_eth_address, deployer_eth_priv_key = cli_utils.load_besu_key(
            "deployer")
        auditor_eth_address, auditor_eth_priv_key = cli_utils.load_besu_key(
            "auditor")
        alice_eth_address, alice_eth_priv_key = cli_utils.load_besu_key(
            "alice")
        bob_eth_address, bob_eth_priv_key = cli_utils.load_besu_key("bob")

    print_balances(web3, deployer_eth_address, auditor_eth_address,     #각 user의 balance output
                   alice_eth_address, bob_eth_address)

    os.system("mkdir deployer")  # deployer
    os.chdir("./deployer")

    token_instance = deploy_token(  # 그냥 토큰 인스턴스화하는거 아닌가? 새로운 erc20 만들어서...deploy된 주소를 가지고 접근해야하니까 사용하려면.....
        web3, deployer_eth_address, deployer_eth_priv_key, DEPLOY_TOKEN_GAS)

    zklay_client, zklay_instance_desc = ZklayClient.deploy( # 우리가 원하는 ㄹㅇ azeroth deploy
        web3,
        client_ctx,
        CIRCUIT, #circuit 이름
        deployer_eth_address, #진짜 이더리움 주소
        deployer_eth_priv_key, # 이더리움 프라이빗 키 
        token_instance.address, #erc20 주소
        DEFAULT_GAS_VALUE) #deploy할 때 필요한 가스 

    token_instance_desc = cli_utils.get_erc20_instance_description(     #token_instance.address
        token_instance.address)

    zklay_desc = cli_utils.MixerDescription(
        zklay_instance_desc, token_instance_desc, client_ctx.env)

    cli_utils.write_mixer_description(INSTANCE_FILE_DEFAULT, zklay_desc)

    mint_token(web3,    # token mint
               token_instance,
               deployer_eth_address,
               deployer_eth_address,
               deployer_eth_priv_key,
               # None,
               EtherValue(DEFAULT_VALUE))

    zklay = zklay_desc.mixer.address
    os.system("echo "+deployer_eth_address+" > eth-address")
    os.chdir(cur_pwd)  # deployer

##################################auditor#########################################
    mkdir_auditor("auditor", auditor_eth_address)

    try:
        if os.path.exists(AUDIT_PUB_FILE):
            raise Exception(f"AuditAddress Pub File {AUDIT_PUB_FILE} exists")

        if os.path.exists(AUDIT_PRIV_FILE):
            raise Exception(f"AuditAddress Priv File {AUDIT_PRIV_FILE} exists")
    except Exception as err:
        print(err)
        sys.exit()

    zklay_audit_address = ZklayAuditAddress.generate_keypair(client_ctx) #audit의 apk, ask 생성

    cli_utils.write_zklay_audit_address_public(
        zklay_audit_address.apk, AUDIT_PUB_FILE)
    print(f"Public AuditAddress written to {AUDIT_PUB_FILE}")

    cli_utils.write_zklay_audit_address_secret(
        zklay_audit_address.ask, AUDIT_PRIV_FILE)
    print(f"Secret AuditAddress written to {AUDIT_PRIV_FILE}")

    print(f"Audit Key Gen : eth_address={auditor_eth_address}")

    auditor_pub = zklay_audit_address.apk

    tx_hash = zklay_client.registerAuditor(     #블록체인에 auditor를 등록하는 부분? 맞음ㅋㅎㅋㅎ
        audit_public_key=zklay_audit_address.apk.apk,
        auditor_eth_address=auditor_eth_address,
        auditor_eth_private_key=auditor_eth_priv_key,
        tx_value=EtherValue(0)
    )

    print_value(tx_hash, name="tx_hash", func_name="registerAuditor")

    mint_token(web3,
               token_instance,
               auditor_eth_address,
               deployer_eth_address,
               deployer_eth_priv_key,
               # None,
               EtherValue(DEFAULT_VALUE))

    os.chdir(cur_pwd)  # auditor


####################################alice#######################################
    mkdir_user("alice", alice_eth_address)
    mint_token(web3,
               token_instance,
               alice_eth_address,
               deployer_eth_address,
               deployer_eth_priv_key,
               # None,
               EtherValue(DEFAULT_VALUE))

    alice = gen_address(zklay_client, alice_eth_address, alice_eth_priv_key)    #alice의 Key 생성
    alice_pub = alice.upk
    alice_priv = alice.usk

    os.chdir(cur_pwd)  # alice



####################################bob#######################################
    mkdir_user("bob", bob_eth_address)

    mint_token(web3,
               token_instance,
               bob_eth_address,
               deployer_eth_address,
               deployer_eth_priv_key,
               # None,
               EtherValue(DEFAULT_VALUE))

    bob = gen_address(zklay_client, bob_eth_address, bob_eth_priv_key)      #bob의 Key 생성
    bob_pub = bob.upk
    bob_priv = bob.usk

    os.chdir(cur_pwd)  # bob

    user_list_path = [
        [alice_pub, alice_priv, "alice"],
        [bob_pub, bob_priv, "bob"]
    ]
    msg = """
        test 1. alice to bob ( valid transfer )
        [dv_ :: 800 | pv :: 1000 | pv' :: 100]
        """

    if client_ctx.env == KLAYTN or client_ctx.env == BESU:
        time.sleep(2)
    print_msg_box(msg=msg, width=91, title="TEST 1.")
    print_balances_token(       #각 user의 token 확인
        token_instance, zklay, auditor_eth_address, alice_eth_address, bob_eth_address)

    pocket = Pocket(    #value pocket
        v_priv=EtherValue(1),
        v_in=EtherValue(1),
        v_out=EtherValue(0)
    )

    if client_ctx.env == KLAYTN or client_ctx.env == BESU:
        time.sleep(2)

    proof = transfer(       #proof만드는것, zkTransfer_{Client}부분
        zklay_client=zklay_client,
        zklay_desc=zklay_desc,
        circuit=CIRCUIT,
        auditor_pub=auditor_pub,
        sender_pub=alice_pub,
        sender_priv=alice_priv,
        receiver_pub=bob_pub,
        pocket=pocket,
        client_ctx=client_ctx,
        sender_address=alice_eth_address,
        receiver_address=bob_eth_address,
        path="alice",
        sender_eth_private_key=alice_eth_priv_key,
    )

    if client_ctx.env == KLAYTN or client_ctx.env == BESU:
        time.sleep(2)
    print_balances_token(
        token_instance, zklay, auditor_eth_address, alice_eth_address, bob_eth_address)

    """
        all sync
    """
    all_sync(
        client_ctx=client_ctx,
        zklay_client=zklay_client,
        receiver_path_list=user_list_path,
    )

    msg = """
        test 2. bob to alice ( valid transfer )
        [dv_ :: 400 | pv :: 1000 | pv' :: 500]
        """

    if client_ctx.env == KLAYTN or client_ctx.env == BESU:
        time.sleep(2)

    print_msg_box(msg=msg, width=91, title="TEST 2.")
    print_balances_token(
        token_instance, zklay, auditor_eth_address, alice_eth_address, bob_eth_address)

    pocket = Pocket(
        v_priv=EtherValue(1),
        v_in=EtherValue(1),
        v_out=EtherValue(0)
    )

    if client_ctx.env == KLAYTN or client_ctx.env == BESU:
        time.sleep(2)
    proof = transfer(
        zklay_client=zklay_client,
        zklay_desc=zklay_desc,
        circuit=CIRCUIT,
        auditor_pub=auditor_pub,
        sender_pub=bob_pub,
        sender_priv=bob_priv,
        receiver_pub=alice_pub,
        pocket=pocket,
        client_ctx=client_ctx,
        sender_address=bob_eth_address,
        receiver_address=alice_eth_address,
        path="bob",
        sender_eth_private_key=bob_eth_priv_key,
    )

    if client_ctx.env == KLAYTN or client_ctx.env == BESU:
        time.sleep(2)

    print_balances_token(
        token_instance, zklay, auditor_eth_address, alice_eth_address, bob_eth_address)

    """
        all sync
    """
    all_sync(
        client_ctx=client_ctx,
        zklay_client=zklay_client,
        receiver_path_list=user_list_path,
    )

    msg = """
        test 3. alice to bob ( valid transfer )
        [dv_ :: 200 | pv :: 500 | pv' :: 300]
        """

    if client_ctx.env == KLAYTN or client_ctx.env == BESU:
        time.sleep(2)

    print_msg_box(msg=msg, width=91, title="TEST 3.")
    print_balances_token(
        token_instance, zklay, auditor_eth_address, alice_eth_address, bob_eth_address)

    pocket = Pocket(
        v_priv=EtherValue(1),
        v_in=EtherValue(1),
        v_out=EtherValue(0)
    )

    if client_ctx.env == KLAYTN or client_ctx.env == BESU:
        time.sleep(2)

    proof = transfer(
        zklay_client=zklay_client,
        zklay_desc=zklay_desc,
        circuit=CIRCUIT,
        auditor_pub=auditor_pub,
        sender_pub=alice_pub,
        sender_priv=alice_priv,
        receiver_pub=bob_pub,
        pocket=pocket,
        client_ctx=client_ctx,
        sender_address=alice_eth_address,
        receiver_address=bob_eth_address,
        path="alice",
        sender_eth_private_key=alice_eth_priv_key,
    )

    if client_ctx.env == KLAYTN or client_ctx.env == BESU:
        time.sleep(2)

    print_balances_token(
        token_instance, zklay, auditor_eth_address, alice_eth_address, bob_eth_address)

    """
        all sync
    """
    all_sync(
        client_ctx=client_ctx,
        zklay_client=zklay_client,
        receiver_path_list=user_list_path,
    )

    # clear_user_dirs(["alice", "bob", "deployer", "auditor"])
