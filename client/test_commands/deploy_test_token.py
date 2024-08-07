# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from zklay.core.contracts import Interface, send_contract_call
from zklay.core.utils import EtherValue, get_zklay_dir
from zklay.core.constants import SOL_COMPILER_VERSION
from zklay.cli.utils import load_eth_address, load_eth_private_key, \
    get_eth_network, open_web3_from_network
from zklay.cli.constants import ETH_ADDRESS_DEFAULT, \
    ETH_NETWORK_FILE_DEFAULT, ETH_NETWORK_DEFAULT
from click import command, argument, option
from os.path import join
from solcx import compile_files, set_solc_version
from typing import Optional, Any


@command()
@option(
    "--eth-addr",
    help=f"Address or address filename (default: {ETH_ADDRESS_DEFAULT})")
@option("--eth-private-key", help="Sender's eth private key file")
@option(
    "--eth-network",
    default=None,
    help="Ethereum RPC endpoint, network or config file "
    f"(default: '{ETH_NETWORK_FILE_DEFAULT}' if it exists, otherwise "
    f"'{ETH_NETWORK_DEFAULT}')")
@argument("mint_amount", type=int)
@argument("recipient_address")
def deploy_test_token(
        eth_network: Optional[str],
        eth_addr: Optional[str],
        eth_private_key: Optional[str],
        mint_amount: int,
        recipient_address: str) -> None:
    """
    Deploy a simple ERC20 token for testing, and mint some for a specific
    address. Print the token address.
    """
    eth_addr = load_eth_address(eth_addr)
    eth_private_key_data = load_eth_private_key(eth_private_key)
    recipient_address = load_eth_address(recipient_address)
    web3 = open_web3_from_network(get_eth_network(eth_network))
    token_instance = deploy_token(
        web3, eth_addr, eth_private_key_data, 4000000) \
        # pylint: disable=no-member
    mint_tx_hash = mint_token(
        web3,
        token_instance,
        recipient_address,
        eth_addr,
        eth_private_key_data,
        EtherValue(mint_amount, 'ether'))
    web3.eth.waitForTransactionReceipt(mint_tx_hash)  # pylint: disable=no-member

    print(token_instance.address)

def compile_token() -> Interface:       #erc20 token compile하는 부분. 표준 interface를 따르는 부분
    """
    Compile the testing ERC20 token contract
    """

    zklay_dir = get_zklay_dir()
    allowed_path = join(
        zklay_dir,
        "zklay_contracts/node_modules/openzeppelin-solidity/contracts")
    path_to_token = join(
        zklay_dir,
        "zklay_contracts/node_modules/openzeppelin-solidity/contracts",
        # "token/ERC20/ERC20Mintable.sol")
        "token/ERC20/presets/ERC20PresetMinterPauser.sol")
    # Compilation
    set_solc_version(SOL_COMPILER_VERSION)
    
    compiled_sol = compile_files([path_to_token], allow_paths=allowed_path)
    # token_interface = compiled_sol[path_to_token + ":ERC20Mintable"]
    token_interface = compiled_sol[path_to_token + ":ERC20PresetMinterPauser"]
    return token_interface


def deploy_token(   #web3 블록체인 어떤걸 쓸건지,, 우리는local로 돌릴거니까 url -> ganache  -> send_contract_call 이 부분 땜에 어떤 블록체인을 쓸건지 인건가? 가나슈무엇?
        web3: Any,
        deployer_address: str,
        deployer_private_key: Optional[bytes],
        deployment_gas: Optional[int]) -> Any:
    """
    Deploy the testing ERC20 token contract
    """
    token_interface = compile_token()
    token = web3.eth.contract(
        abi=token_interface['abi'], bytecode=token_interface['bin'])
    constructor_call = token.constructor("NAME","SYM")

    tx_hash = send_contract_call(   #contract을 실행시키는 부분?......
        web3=web3,
        call=constructor_call,
        sender_eth_addr=deployer_address,
        sender_eth_private_key=deployer_private_key,
        value= None,
        gas=deployment_gas)
    tx_receipt = web3.eth.waitForTransactionReceipt(tx_hash)

    token = web3.eth.contract(
        address=tx_receipt.contractAddress,
        abi=token_interface['abi'],
    )
    return token


def mint_token(
        web3: Any,
        token_instance: Any,
        spender_address: str,
        deployer_address: str,
        deployer_private_key: Optional[bytes],
        token_amount: EtherValue) -> bytes:
    mint_call = token_instance.functions.mint(spender_address, token_amount.wei)
    return send_contract_call(
        web3=web3,
        call=mint_call,
        sender_eth_addr=deployer_address,
        sender_eth_private_key=deployer_private_key)


if __name__ == "__main__":
    deploy_test_token()  # pylint: disable=no-value-for-parameter
