#!/usr/bin/env python3


from unittest import TestCase
import test_commands.mock as mock
import zklay.cli.utils as cli_utils 
import zklay.core.utils as core_utils
import zklay.cli.constants as cli_constants
import zklay.core.constants as constants
import zklay.core.contracts as contracts
from zklay.core.context import ClientConfig
from zklay.core.zklay_audit_address import ZklayAuditAddress
from zklay.core.zklay_address import ZklayAddress
from zklay.cli.constants import INSTANCE_FILE_DEFAULT
from zklay.core.zklay_client import ZklayClient, TransParameters
from test_commands.deploy_test_token import deploy_token, mint_token
from zklay.core.utils import EtherValue, Pocket
from zklay.cli.scenario import path_wrapper
from zklay.core.zklay_snark import VerificationKey, snark
from typing import Tuple, Any, Optional, List, Dict
import os, json
from os.path import exists

DEFAULT_VALUE = 100000
DEPLOY_TOKEN_GAS = 19000000
DEFAULT_GAS_VALUE = 20000000
ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"

CIRCUIT = "ZKlay"

GANACHE = "ganache"
KLAYTN = "klaytn"
BESU = "besu"

TEST_FILE_PATH = constants.CLIENT_PATH + "/TEST"
TEST_TXS_FILE_PATH = TEST_FILE_PATH + "/rollup_txs"
TEST_TX_FILE_NAME = "tx_"

DEFAULT_DEPLOYER = "/default_deployer"
DEFAULT_AUDITOR = "/default_auditor"
DEFAULT_ALICE = "/default_alice"
DEFAULT_BOB = "/default_bob"

class Scenario(TestCase) :
    def Scenario(self, env, depth, hash, zksnark, ec, scope):
        cur_pwd = os.getcwd()
        ctx = ClientConfig(
            env = env,
            instance_file = cli_constants.INSTANCE_FILE_DEFAULT,
            token_instance_file = cli_constants.TOKEN_INSTANCE_FILE_DEFAULT,
            address_file = cli_constants.ZKLAY_SECRET_ADDRESS_FILE_DEFAULT,
            audit_address_file =cli_constants.ZKLAY_AUDIT_SECRET_ADDRESS_FILE_DEFAULT,
            wallet_dir = cli_constants.WALLET_DIR_DEFAULT,
            depth = depth,
            hash = hash,
            zksnark = zksnark,
            ec = ec
        )

        web3, eth = mock.open_test_web3(env)

        def get_address_ganache(eth: Any, idx: int) -> Tuple[str, None]:
            return eth.accounts[idx], None

        if env == GANACHE:
            deployer_eth_address, deployer_eth_priv_key = get_address_ganache(
                eth, 0)
            auditor_eth_address, auditor_eth_priv_key = get_address_ganache(eth, 1)
            alice_eth_address, alice_eth_priv_key = get_address_ganache(eth, 2)
            bob_eth_address, bob_eth_priv_key = get_address_ganache(eth, 3)
        elif env == KLAYTN:
            deployer_eth_address, deployer_eth_priv_key = mock.create_user(
                web3, "deployer")
            auditor_eth_address, auditor_eth_priv_key = mock.create_user(
                web3, "auditor")
            alice_eth_address, alice_eth_priv_key = mock.create_user(web3, "alice")
            bob_eth_address, bob_eth_priv_key = mock.create_user(web3, "bob")
        elif env == BESU:
            deployer_eth_address, deployer_eth_priv_key = cli_utils.load_besu_key(
                "deployer")
            auditor_eth_address, auditor_eth_priv_key = cli_utils.load_besu_key(
                "auditor")
            alice_eth_address, alice_eth_priv_key = cli_utils.load_besu_key(
                "alice")
            bob_eth_address, bob_eth_priv_key = cli_utils.load_besu_key("bob")

        token_instance = deploy_token(web3, deployer_eth_address, deployer_eth_priv_key, DEPLOY_TOKEN_GAS)

        zklay_client, zklay_instance_desc = Scenario._test_deploy(
            web3,
            deployer_eth_address,
            deployer_eth_priv_key,
            DEPLOY_TOKEN_GAS,
            CIRCUIT,
            ctx,
            depth
        )

        token_instance_desc = cli_utils.get_erc20_instance_description(token_instance.address)
    
        zklay_desc = cli_utils.MixerDescription(zklay_instance_desc, token_instance_desc, env)

        cli_utils.write_mixer_description(INSTANCE_FILE_DEFAULT,zklay_desc)

        mint_token(web3,
                token_instance,
                deployer_eth_address,
                deployer_eth_address,
                deployer_eth_priv_key,
                EtherValue(DEFAULT_VALUE))

        zklay = zklay_desc.mixer.address
        
        auditor = Scenario.gen_auditor(ctx)

        tx_hash = zklay_client.registerAuditor(
            audit_public_key = int(auditor.apk.apk),
            auditor_eth_address = auditor_eth_address,
            auditor_eth_private_key =  auditor_eth_priv_key,
            tx_value = EtherValue(0)
        )
    
        alice = Scenario.gen_user(ctx, DEFAULT_ALICE)
        bob = Scenario.gen_user(ctx, DEFAULT_BOB)
    
        alice_addr = core_utils.int256_to_bytes(int(alice.upk.addr))

        tx_hash = zklay_client.registerUser(
            addr=alice_addr,
            user_eth_address=alice_eth_address,
            user_eth_private_key=alice_eth_priv_key,
            tx_value=EtherValue(0))

        bob_addr = core_utils.int256_to_bytes(int(bob.upk.addr))

        tx_hash = zklay_client.registerUser(
            addr=bob_addr,
            user_eth_address=bob_eth_address,
            user_eth_private_key=bob_eth_priv_key,
            tx_value=EtherValue(0))

        pocket = Pocket(
            v_priv=EtherValue(1),
            v_in=EtherValue(1),
            v_out=EtherValue(0)
        )

        zklay_wallet = cli_utils.open_zklay_wallet(
            zklay_client.zklay_instance,
            alice.usk,
            ctx
        )

        for i in range(scope[0], scope[1]):
            file_name = TEST_TX_FILE_NAME + str(i) + ".json"
            file_path = TEST_TXS_FILE_PATH + "/" + file_name 
            # if exists(file_path) :
            #     pass
            # else :
            os.chdir(TEST_FILE_PATH + DEFAULT_DEPLOYER)
            _, rollup_param = zklay_client.create_trans_args(
                circuit_name = CIRCUIT,
                zklay_wallet = zklay_wallet,
                auditor_pub = auditor.apk,
                sender_pub = alice.upk,
                sender_priv = alice.usk,
                receiver_pub = bob.upk,
                pocket = pocket,
                toEoA = bob_eth_address
            )
            os.chdir(cur_pwd)
            print(rollup_param.to_json())
            rollup_param.write_rollup_param(TEST_TX_FILE_NAME + str(i) + ".json", TEST_TXS_FILE_PATH)
        

    @staticmethod
    @path_wrapper(os.getcwd())
    def _test_deploy(
        web3: Any,
        deployer_eth_address:str,
        deployer_eth_private_key: bytes,
        deploy_gas: int,
        circuit: str,
        ctx: Any,
        depth: str,
        token_address: str = None,
        file_path: Optional[str] = DEFAULT_DEPLOYER) -> Tuple[Any, Any]:

        contracts_dir = core_utils.get_contracts_dir()
        contract_name = cli_utils.get_contract_name(ctx)
        mixer_src = os.path.join(contracts_dir, contract_name + ".sol")

        vk_file = TEST_FILE_PATH + file_path + "/" + cli_constants.TEST_VK_FILE_NAME
        if exists(vk_file):
            vk = VerificationKey.from_json_file(vk_file, False)
            vk_contract_parameter = VerificationKey.verification_key_to_contract_parameters(vk)
        else:
            deployer_path = TEST_FILE_PATH + file_path
            os.mkdir(deployer_path, mode=0o777)
            os.chdir(deployer_path)
            Snark = snark(ctx)
            context_id = Snark.get_context_id(name=circuit)
            Snark.Gen(context_id=context_id)
            vk = VerificationKey.from_list(
                Snark.GetVerificationKey(context_id=context_id))
            with open(vk_file, 'w') as f :
                f.write(vk.to_json())
            vk_contract_parameter = VerificationKey.verification_key_to_contract_parameters(vk)

        constructor_parameters: List[Any] = [
            int(depth),
            token_address or ZERO_ADDRESS,     # token
            vk_contract_parameter,  # vk
            cli_utils.get_hash_num(ctx.hash)
        ]   

        mixer_description = contracts.InstanceDescription.deploy(
            web3,
            mixer_src,
            contract_name,
            deployer_eth_address,
            deployer_eth_private_key,
            deploy_gas,
            compiler_flags={},
            args=constructor_parameters)
        zklay_instance = mixer_description.instantiate(web3)
        client = ZklayClient(web3, zklay_instance, ctx)

        return client, mixer_description

    @staticmethod
    @path_wrapper(os.getcwd())
    def gen_auditor(ctx: Any, file_path: Optional[str] = DEFAULT_AUDITOR) :
        auditor_pub_file = cli_constants.ZKLAY_AUDIT_PUBLIC_ADDRESS_FILE_DEFAULT
        auditor_priv_file = cli_constants.ZKLAY_AUDIT_SECRET_ADDRESS_FILE_DEFAULT
        auditor_path = TEST_FILE_PATH + file_path
        auditor_file_path = auditor_path + "/" + auditor_pub_file

        if exists(auditor_file_path):
            os.chdir(auditor_path)
            auditor = cli_utils.load_zklay_audit_address(ctx)
        else:
            os.mkdir(auditor_path, mode=0o777)
            os.chdir(auditor_path)
            auditor = ZklayAuditAddress.generate_keypair(ctx)
        
            cli_utils.write_zklay_audit_address_public(auditor.apk, auditor_pub_file)
            cli_utils.write_zklay_audit_address_secret(auditor.ask, auditor_priv_file)

        return auditor

    @staticmethod
    @path_wrapper(os.getcwd())
    def gen_user(ctx: Any, file_path: str):
        user_pub_file = cli_constants.ZKLAY_PUBLIC_ADDRESS_FILE_DEFAULT
        user_priv_file = cli_constants.ZKLAY_SECRET_ADDRESS_FILE_DEFAULT
        user_path = TEST_FILE_PATH + file_path
        user_file_path = user_path + "/" + user_pub_file

        if exists(user_file_path):
            os.chdir(user_path)
            user = cli_utils.load_zklay_address(ctx, user_path)
        else:
            os.mkdir(user_path, mode=0o777)
            os.chdir(user_path)
            user = ZklayAddress.generate_keypair(ctx)

            cli_utils.write_zklay_address_public(user.upk, user_pub_file)
            cli_utils.write_zklay_address_secret(user.usk, user_priv_file)
        
        return user


if __name__ == "__main__" :
    env = "ganache"
    depth = "32"
    hash = "Poseidon"
    zksnark = constants.GROTH16_ZKSNARK
    ec = constants.ELLIPTIC_CURVE_BLS12_381
    scope = [0,1]
    Scenario().Scenario(env, depth, hash, zksnark, ec, scope)