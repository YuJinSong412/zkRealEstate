# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
# Copyright (c) 2021-2021 Zkrypto Inc.
#
# SPDX-License-Identifier: LGPL-3.0+

from __future__ import annotations
from click import ClickException
import json
import os
from os.path import exists, join, splitext
from typing import Dict, Tuple, Optional, Callable, Any, List
from web3 import Web3
from zklay.core.constants import GROTH16_ZKSNARK, ELLIPTIC_CURVE_BN256,\
    CLIENT_PATH
from zklay.cli.constants import WALLET_USERNAME, ETH_ADDRESS_DEFAULT, \
    ETH_PRIVATE_KEY_FILE_DEFAULT, ETH_RPC_ENDPOINT_DEFAULTS, \
    ETH_NETWORK_FILE_DEFAULT, ETH_NETWORK_DEFAULT, CONFIG_FILE, HASH_TYPE, CLIENT_CONFIG_FILE
from zklay.core.zklay_address import \
    ZklayAddressPub, ZklayAddressPriv, ZklayAddress
from zklay.core.zklay_audit_address import \
    ZklayAuditAddressPub, ZklayAuditAddressPriv, ZklayAuditAddress
from zklay.core.contracts import \
    InstanceDescription, get_block_number, compile_files
from zklay.core.zklay_wallet import ZklayNoteDescription, ZklayWallet
from zklay.core.zklay_client import ZklayClient, get_trans_result
from zklay.core.utils import \
    open_web3, short_commitment, get_zklay_dir, from_zklay_units, get_zklay_client_dir, int256_to_bytes
from zklay.core.zklay_encryption import PublicKeyEncryptionSystem
from zklay.cli.debugger import print_wrapper, print_msg_box
from zklay.core.context import ClientConfig, NetworkConfig


def get_eth_network(eth_network: Optional[str]) -> NetworkConfig:
    """
    Parse the `eth_network` parameter to extract a URL. If `eth_network` does
    not contain a URL, try interpreting it as a network name, otherwise
    interpret it as a file to load the network config from. Fall back to a
    default network config filename, and finally the default network name.
    """
    if eth_network is None:
        if exists(ETH_NETWORK_FILE_DEFAULT):
            eth_network = ETH_NETWORK_FILE_DEFAULT
        else:
            eth_network = ETH_NETWORK_DEFAULT

    # eth_network = BAOBOB_NETWORK_DEFAULT # fix

    if eth_network.startswith("http"):
        # When given only a url, assume the default network name
        return NetworkConfig(ETH_NETWORK_DEFAULT, eth_network)

    # Try loading from a file
    if exists(eth_network):
        with open(eth_network) as network_f:
            return NetworkConfig.from_json(network_f.read())

    # Assume a network name
    try:
        endpoint = ETH_RPC_ENDPOINT_DEFAULTS[eth_network]
        return NetworkConfig(eth_network, endpoint)
    except KeyError as ex:
        raise ClickException(
            f"invalid network name / url: {eth_network}") from ex


def open_web3_from_network(eth_net: NetworkConfig) -> Any:
    return open_web3(
        url=eth_net.endpoint,
        certificate=eth_net.certificate,
        insecure=eth_net.insecure)


def open_web3_from_ctx(ctx: ClientConfig) -> Any:
    eth_net = get_eth_network(ctx.env)
    return open_web3_from_network(eth_net)


class MixerDescription:
    """
    Holds an InstanceDescription for the mixer contract, and optionally an
    InstanceDescription for the token contract.
    """

    def __init__(
            self,
            mixer: InstanceDescription,
            token: Optional[InstanceDescription],
            env: Optional[str]):
        self.mixer = mixer
        self.token = token
        self.env = env

    def to_json(self) -> str:
        json_dict = {
            "mixer": self.mixer.to_json_dict()
        }
        if self.token:
            json_dict["token"] = self.token.to_json_dict()
        if self.env:
            json_dict["env"] = self.env
        return json.dumps(json_dict)

    @staticmethod
    def from_json(json_str: str) -> MixerDescription:
        json_dict = json.loads(json_str)
        mixer = InstanceDescription.from_json_dict(json_dict["mixer"])
        token_dict = json_dict.get("token", None)
        token = InstanceDescription.from_json_dict(token_dict) \
            if token_dict else None
        env = json_dict['env']
        return MixerDescription(mixer, token, env)


def get_erc20_abi() -> Dict[str, Any]:
    zklay_dir = get_zklay_dir()
    openzeppelin_dir = join(
        zklay_dir, "zklay_contracts", "node_modules", "openzeppelin-solidity")
    ierc20_path = join(
        openzeppelin_dir, "contracts", "token", "ERC20", "IERC20.sol")
    compiled_sol = compile_files([ierc20_path])
    erc20_interface = compiled_sol[ierc20_path + ":IERC20"]
    return erc20_interface["abi"]


def get_erc20_instance_description(token_address: str) -> InstanceDescription:
    return InstanceDescription(token_address, get_erc20_abi())


def get_token_description(token: Any) -> InstanceDescription:
    return InstanceDescription(token.address, token.abi)


def write_mixer_description(
        mixer_desc_file: str,
        mixer_desc: MixerDescription) -> None:
    """
    Write the mixer (and token) instance information
    """
    with open(mixer_desc_file, "w") as instance_f:
        instance_f.write(mixer_desc.to_json())


def write_token_description(
        desc_file: str,
        desc: InstanceDescription) -> None:

    token = {
        "token": desc.to_json_dict()
    }
    with open(desc_file, "w") as token_instance_f:
        token_instance_f.write(json.dumps(token))


def load_mixer_description(mixer_description_file: str) -> MixerDescription:
    """
    Return mixer and token (if present) contract instances
    """
    with open(mixer_description_file, "r") as desc_f:
        return MixerDescription.from_json(desc_f.read())


def load_zklay_description(mixer_description_file: str) -> MixerDescription:
    """
    Return mixer and token (if present) contract instances
    """
    with open(mixer_description_file, "r") as desc_f:
        return MixerDescription.from_json(desc_f.read())


def load_token_description(decription_file: str) -> MixerDescription:
    with open(decription_file, "r") as f:
        json_dict = json.loads(f.read())
        token_dict = json_dict.get("token", None)
    return InstanceDescription(address=token_dict["address"], abi=token_dict["abi"])


def load_mixer_description_from_ctx(ctx: ClientConfig) -> MixerDescription:
    return load_mixer_description(ctx.instance_file)


def load_zklay_description_from_ctx(ctx: ClientConfig) -> MixerDescription:
    return load_zklay_description(ctx.instance_file)


def load_token_description_from_ctx(ctx: ClientConfig) -> InstanceDescription:
    return load_token_description(ctx.token_instance_file)


def get_zklay_address_file(ctx: ClientConfig) -> str:
    return ctx.address_file


def get_zklay_audit_address_file(ctx: ClientConfig) -> str:
    return ctx.audit_address_file


def load_zklay_address_public(ctx: ClientConfig, rev_path=None) -> ZklayAddressPub:
    """
    Load a ZklayAddressPub from a key file.
    """
    secret_key_file = get_zklay_address_file(ctx)
    pub_addr_file = pub_address_file(secret_key_file)
    if rev_path != None:
        pub_addr_file = rev_path+"/"+pub_addr_file
    with open(pub_addr_file, "r") as pub_addr_f:
        return ZklayAddressPub.parse(pub_addr_f.read())


def load_zklay_audit_address_public(ctx: ClientConfig) -> ZklayAuditAddressPub:
    """
    Load a AuditAddressPub from a key file.
    """
    secret_key_file = get_zklay_audit_address_file(ctx)
    pub_addr_file = pub_address_file(secret_key_file)
    with open(pub_addr_file, "r") as pub_addr_f:
        return ZklayAuditAddressPub.parse(pub_addr_f.read())


def write_zklay_address_public(
        pub_addr: ZklayAddressPub, pub_addr_file: str) -> None:
    """
    Write a ZklayAddressPub to a file
    """
    with open(pub_addr_file, "w") as pub_addr_f:
        pub_addr_f.write(str(pub_addr))


def write_zklay_audit_address_public(
        pub_addr: ZklayAuditAddressPub, pub_addr_file: str) -> None:
    """
    Write a AuditAddressPub to a file
    """
    try:
        with open(pub_addr_file, "w") as pub_addr_f:
            pub_addr_f.write(pub_addr.to_json())
    except:
        print("write zklay audit_address_public")


# load zklay address secret
def load_zklay_address_secret(ctx: ClientConfig, rev_path=None) -> ZklayAddressPriv:
    """
    Read ZklayAddressPriv
    """
    addr_file = get_zklay_address_file(ctx)
    if rev_path != None:
        addr_file = rev_path+"/"+addr_file
    with open(addr_file, "r") as addr_f:
        return ZklayAddressPriv.from_json(addr_f.read())


def load_zklay_audit_address_secret(ctx: ClientConfig) -> ZklayAuditAddressPriv:
    """
    Read AuditAddressPriv
    """
    addr_file = get_zklay_audit_address_file(ctx)
    with open(addr_file, "r") as addr_f:
        return ZklayAuditAddressPriv.from_json(addr_f.read())


def write_zklay_address_secret(
        secret_addr: ZklayAddressPriv, addr_file: str) -> None:
    """
    Write ZklayAddressPriv to file
    """
    with open(addr_file, "w") as addr_f:
        addr_f.write(secret_addr.to_json())


def write_zklay_audit_address_secret(
        secret_addr: ZklayAuditAddressPriv, addr_file: str) -> None:
    """
    Write AuditAddressPriv to file
    """
    with open(addr_file, "w") as addr_f:
        addr_f.write(secret_addr.to_json())


def load_zklay_address(ctx: ClientConfig, rev_path=None) -> ZklayAddress:
    """
    Load a ZklayAddress from a file path, and return as a ZklayAddress
    """
    return ZklayAddress.from_secret_public(
        load_zklay_address_secret(ctx, rev_path),
        load_zklay_address_public(ctx, rev_path))


def load_zklay_audit_address(ctx: ClientConfig) -> ZklayAuditAddress:
    """
    Load a AuditAddress secret from a file,
    and the associated public address,
    and return as a AuditAddress.
    """
    return ZklayAuditAddress.from_secret_public(
        load_zklay_audit_address_public(ctx),
        load_zklay_audit_address_secret(ctx)
    )


def load_client_config(client_config_file: Optional[str] = CLIENT_CONFIG_FILE) -> ClientConfig:
    client_path = CLIENT_PATH + "/" + client_config_file 
    with open(client_path, "r") as client_config_f:
        return ClientConfig.from_json(client_config_f.read())


def write_client_config(ctx: ClientConfig, client_config_file: Optional[str] = CLIENT_CONFIG_FILE) -> None:
    client_path = CLIENT_PATH + "/" + client_config_file 
    with open(client_path, "w") as client_config_f:
        client_config_f.write(ctx.to_json())


def open_zklay_wallet(
        zklay_instance: Any,
        js_secret: ZklayAddressPriv,
        ctx: ClientConfig) -> ZklayWallet:
    """
    Load a wallet using a secret key.
    """
    public_enc = PublicKeyEncryptionSystem(ctx, js_secret.usk)

    return ZklayWallet(
        zklay_instance, WALLET_USERNAME, ctx, public_enc)


def do_sync_trans(
        web3: Any,
        wallet: ZklayWallet,
        callback: Optional[Callable[[ZklayNoteDescription], None]] = None,
        batch_size: Optional[int] = None) -> int:

    def _do_sync_trans() -> int:
        wallet_next_block = wallet.get_next_block()
        chain_block_number = get_block_number(web3)

        if chain_block_number >= wallet_next_block:
            print(
                f"SYNCHING blocks ({wallet_next_block} - {chain_block_number})")

            for trans_result in get_trans_result(
                web3,
                wallet.mixer_instance,
                wallet_next_block,
                chain_block_number,
                batch_size
            ):
                for zklay_note_desc in wallet.receive_notes(trans_result.output_events):
                    if callback:
                        callback(zklay_note_desc)

                for trans in trans_result.output_events:
                    nullifier = int256_to_bytes(trans_result.nullifier)
                    spent_commit = wallet.mark_nullifier_used(nullifier)
                    if spent_commit:
                        msg = f" Nullifier: [{nullifier.hex()[0:8]}], " + \
                            f" SPENT: [{spent_commit}]"
                        print_msg_box(msg)

            wallet.update_and_save_state(next_block=chain_block_number + 1)

        return chain_block_number

    return _do_sync_trans()


def pub_address_file(addr_file: str) -> str:
    """
    The name of a public address file, given the secret address file.
    """
    return splitext(addr_file)[0] + ".pub"


def find_pub_address_file(base_file: str) -> str:
    """
    Given a file name, which could point to a private or public key file, guess
    at the name of the public key file.
    """
    pub_addr_file = pub_address_file(base_file)
    if exists(pub_addr_file):
        return pub_addr_file
    if exists(base_file):
        return base_file

    raise ClickException(f"No public key file {pub_addr_file} or {base_file}")


def create_zklayclient_and_zklaydesc(
        ctx: ClientConfig,
) -> Tuple[ZklayClient, MixerDescription]:

    web3 = open_web3_from_ctx(ctx)
    zklay_desc = load_zklay_description_from_ctx(ctx)
    zklay_instance = zklay_desc.mixer.instantiate(web3)
    zklay_client = ZklayClient(
        web3, zklay_instance, ctx)
    return (zklay_client, zklay_desc)


def zklay_note_short(zklay_note_desc: ZklayNoteDescription) -> str:
    """
    Generate a short human-readable description of a commitment.
    """
    print(f"dv :: {int(zklay_note_desc.note.dv,16)}")
    value = from_zklay_units(int(zklay_note_desc.note.dv, 16)).ether()
    cm = short_commitment(zklay_note_desc.commitment)
    return f"{cm} : value={value} ETH, addr={zklay_note_desc.address}"


def zklay_note_short_print(zklay_note_desc: ZklayNoteDescription) -> None:
    msg = f" NEW NOTE : {zklay_note_short(zklay_note_desc)}"
    print_msg_box(msg, width=91)


def load_eth_address(eth_addr: Optional[str] = None, path: Optional[str] = None) -> str:
    """
    Given an --eth-addr command line param, either parse the address, load from
    the file, or use a default file name.
    """
    eth_addr = eth_addr or ETH_ADDRESS_DEFAULT
    if eth_addr.startswith("0x"):
        return Web3.toChecksumAddress(eth_addr)
    if path:
        eth_addr = path+"/"+eth_addr
    if exists(eth_addr):
        with open(eth_addr, "r") as eth_addr_f:
            return Web3.toChecksumAddress(eth_addr_f.read().rstrip())
    raise ClickException(f"could find file or parse eth address: {eth_addr}")


def write_eth_address(eth_addr: str, eth_addr_file: str) -> None:
    if exists(eth_addr_file):
        raise ClickException(
            f"refusing to overwrite address \"{eth_addr_file}\"")
    with open(eth_addr_file, "w") as eth_addr_f:
        eth_addr_f.write(eth_addr)


def load_eth_private_key(private_key_file: Optional[str] = None, path: Optional[str] = None) -> Optional[bytes]:
    private_key_file = private_key_file or ETH_PRIVATE_KEY_FILE_DEFAULT
    if path:
        private_key_file = path+"/"+private_key_file
    if exists(private_key_file):
        with open(private_key_file, "rb") as private_key_f:
            return private_key_f.read(32)
    return None


def write_eth_private_key(private_key: bytes, private_key_file: str) -> None:
    if exists(private_key_file):
        raise ClickException(
            f"refusing to overwrite private key \"{private_key_file}\"")
    with open(private_key_file, "wb") as private_key_f:
        private_key_f.write(private_key)


@print_wrapper(1)
def get_user_audit(
        client_ctx: ClientConfig,
        auditor: ZklayAuditAddress,
        zklay_client: Any,
        tx_hash: Optional[str],
        start_block: Optional[int] = 1
) -> List[str]:
    pub_enc = PublicKeyEncryptionSystem(client_ctx, auditor.ask.ask)
    if tx_hash != None:
        start_block = zklay_client.web3.eth.getTransaction(tx_hash)[
            "blockNumber"]
    cnt = 1
    end_block = start_block if start_block != 1 else get_block_number(
        zklay_client.web3)
    for trans_result in get_trans_result(
            zklay_client.web3,
            zklay_client.zklay_instance,
            start_block,
            end_block):
        for trans in trans_result.output_events:
            res = pub_enc.decrypt(trans.p_ct, True)
            msg = f"| [Amount   ] :: {res[1]} \n" \
                f"| [Receiver ] :: {str(res[2])} \n"
            print_msg_box(msg, width=95, title=f"Audit [{cnt}]")
            cnt += 1


def write_config_cache(hash_name: str, depth: str):

    assert HASH_TYPE[hash_name], "Invalid hash name"

    config_dict = {
        "hash_name": hash_name,
        "depth": depth
    }
    with open(get_zklay_client_dir() + "/" + CONFIG_FILE, "w") as config:
        config.write(json.dumps(config_dict))


def load_config_cache() -> str:
    with open(get_zklay_client_dir() + "/" + CONFIG_FILE, "r") as _config:
        return json.load(_config)


def load_besu_key(entity: str) -> Tuple[Any, Any]:
    file_name = entity + "_besu.key"
    assert os.path.isfile(file_name)

    with open(file_name) as key_file:
        data = json.loads(key_file.read())
        address = data["address"]
        privateKey = data["privateKey"]
        return address, privateKey


def get_hash_num(hash_type: str) -> int:
    if hash_type == "MiMC7":
        return 1
    elif hash_type == "SHA256":
        return 2
    elif hash_type == "Poseidon":
        return 3


def get_contract_name(ctx: ClientConfig) -> str:
    _contract_name = ""
    if (ctx.zksnark == GROTH16_ZKSNARK):
        _contract_name += "Groth16"

    if (ctx.ec == ELLIPTIC_CURVE_BN256):
        _contract_name += "AltBN128"
    else:
        _contract_name += "BLS12_381"

    return _contract_name + "Mixer"
