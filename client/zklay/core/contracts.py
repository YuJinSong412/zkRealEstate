#!/usr/bin/env python3

# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
# Copyright (c) 2021 Zkrypto

# SPDX-License-Identifier: LGPL-3.0+

from __future__ import annotations
from zklay.core.utils import EtherValue
from zklay.core.constants import SOL_COMPILER_VERSION, DEFAULT_GAS
from web3.utils.contracts import find_matching_event_abi  # type: ignore
from eth_utils import event_abi_to_log_topic
from web3.utils.events import get_event_data  # type: ignore
import solcx
from typing import Dict, List, Iterator, Optional, Union, Iterable, Any

# Avoid trying to read too much data into memory
SYNC_BLOCKS_PER_BATCH = 1000
CHAIN_ID: int = 1001
Interface = Dict[str, Any]

DEFAULT_VALUE = 1000000


class InstanceDescription:
    """
    Minimal data required to instantiate the in-memory interface to a contract.
    """

    def __init__(self, address: str, abi: Dict[str, Any]):
        self.address = address
        self.abi = abi

    def to_json_dict(self) -> Dict[str, Any]:
        return {
            "address": self.address,
            "abi": self.abi
        }

    @staticmethod
    def from_json_dict(desc_json: Dict[str, Any]) -> InstanceDescription:
        return InstanceDescription(desc_json["address"], desc_json["abi"])

    @staticmethod
    def deploy(
            web3: Any,
            source_file: str,
            contract_name: str,
            deployer_eth_address: str,
            deployer_eth_private_key: Optional[bytes],
            deployment_gas: int,
            compiler_flags: Dict[str, Any] = None,
            args: Iterable[Any] = None) -> InstanceDescription:
        """
        Compile and deploy a contract, returning the live instance and an instance
        description (which the caller should save in order to access the
        instance in the future).
        """
        compiled = InstanceDescription.compile(
            source_file, contract_name, compiler_flags)
        assert compiled
        instance_desc = InstanceDescription.deploy_from_compiled(
            web3,
            deployer_eth_address,
            deployer_eth_private_key,
            deployment_gas,
            compiled,
            *(args or []))
        print(
            f"deploy: contract: {contract_name} "
            f"to address: {instance_desc.address}")
        return instance_desc

    @staticmethod
    def deploy_from_compiled(
            web3: Any,
            deployer_eth_address: str,
            deployer_eth_private_key: Optional[bytes],
            deployment_gas: int,
            compiled: Any,
            *args: Any) -> InstanceDescription:
        contract = web3.eth.contract(
            abi=compiled['abi'], bytecode=compiled['bin'])
        construct_call = contract.constructor(*args)
        tx_hash = send_contract_call(
            web3,
            construct_call,
            deployer_eth_address,
            deployer_eth_private_key,
            None,
            deployment_gas)

        tx_receipt = web3.eth.waitForTransactionReceipt(tx_hash, 10000)
        contract_address = tx_receipt['contractAddress']
        print(
            f"deploy:   tx_hash={tx_hash[0:8].hex()}, " +
            f"  gasUsed={tx_receipt.gasUsed}, status={tx_receipt.status}")
        return InstanceDescription(contract_address, compiled['abi'])

    @staticmethod
    def compile(
            source_file: str,
            contract_name: str,
            compiler_flags: Dict[str, Any] = None) \
            -> Any:
        compiled_all = compile_files([source_file], **(compiler_flags or {}))
        assert compiled_all
        compiled = compiled_all[f"{source_file}:{contract_name}"]
        assert compiled
        return compiled

    def instantiate(self, web3: Any) -> Any:
        """
        Return the instantiated contract
        """
        return web3.eth.contract(address=self.address, abi=self.abi)


def get_block_number(web3: Any) -> int:
    return web3.eth.blockNumber


def install_sol() -> None:
    solcx.install_solc(SOL_COMPILER_VERSION)


def compile_files(files: List[str], **kwargs: Any) -> Any:
    """
    Wrapper around solcx which ensures the required version of the compiler is
    used.
    """
    solcx.set_solc_version(SOL_COMPILER_VERSION)
    return solcx.compile_files(files, optimize=True, **kwargs)


def send_contract_call(
        web3: Any,
        call: Any,
        sender_eth_addr: str,
        sender_eth_private_key: Optional[bytes] = None,
        value: Optional[EtherValue] = None,
        gas: Optional[int] = 10000000) -> bytes:
    """
    Broadcast a transaction for a contract call, handling the difference
    between hosted keys (sender_eth_private_key is None) and local keys
    (sender_eth_private_key is not None). Returns the hash of the broadcast
    transaction.

    """
    tx_desc: Dict[str, Union[str, int]] = {'from': sender_eth_addr}
    if value:
        tx_desc["value"] = value.wei
    if gas:
        tx_desc["gas"] = gas
    if sender_eth_private_key:
        tx_desc["gas"] = gas  # klaytn
        tx_desc["nonce"] = web3.eth.getTransactionCount(
            sender_eth_addr, "pending")  # ganache
        # tx_desc["gasPrice"] = web3.eth.gasPrice # ganache
        # tx_desc["chainId"] = 1001 # klaytn baobob
        # tx_desc["chainId"] = 942523 # klaytn
        tx_desc["chainId"] = 1337  # besu
        transaction = call.buildTransaction(tx_desc)
        signed_tx = web3.eth.account.signTransaction(
            transaction, sender_eth_private_key)

        return web3.eth.sendRawTransaction(signed_tx.rawTransaction)

    # Hosted path
    return call.transact(tx_desc)


def local_contract_call(
        call: Any,
        sender_eth_addr: str,
        value: Optional[EtherValue] = None,
        gas: Optional[int] = None) -> Any:
    """
    Make a contract call locally on the RPC host and return the result. Does
    not create a transaction.
    """
    tx_desc: Dict[str, Union[str, int]] = {'from': sender_eth_addr}
    if value:
        tx_desc["value"] = value.wei
    if gas:
        tx_desc["gas"] = gas
    return call.call(tx_desc)


def get_event_logs(
        web3: Any,
        instance: Any,
        event_name: str,
        start_block: int,
        end_block: int,
        batch_size: Optional[int]) -> Iterator[Any]:
    """
    Query the attached node for all events emitted by the given contract
    instance, with the given name. Yields an iterator of event-specific objects
    to be decoded by the caller.
    """
    contract_address = instance.address
    event_abi = find_matching_event_abi(instance.abi, event_name=event_name)
    log_topic = event_abi_to_log_topic(event_abi)
    batch_size = batch_size or SYNC_BLOCKS_PER_BATCH

    while start_block <= end_block:
        # Filters are *inclusive* wrt "toBlock", hence the -1 here, and +1 to
        # set start_block before iterating.
        to_block = min(start_block + batch_size - 1, end_block)
        filter_params = {
            'fromBlock': start_block,
            'toBlock': to_block,
            'address': contract_address,
        }

        logs = web3.eth.getLogs(filter_params)
        for log in logs:
            if log_topic == log['topics'][0]:
                yield get_event_data(event_abi, log)
        start_block = to_block + 1


def get_logs(
        web3: Any,
        instance: Any,
        start_block: int,
        end_block: int,
        batch_size: Optional[int] = SYNC_BLOCKS_PER_BATCH) -> Iterator[Any]:

    contract_address = instance.address
    while start_block <= end_block:
        # Filters are *inclusive* wrt "toBlock", hence the -1 here, and +1 to
        # set start_block before iterating.
        to_block = min(start_block + batch_size - 1, end_block)
        filter_params = {
            'fromBlock': start_block,
            'toBlock': to_block,
            'address': contract_address,
        }

        logs = web3.eth.getLogs(filter_params)
        for log in logs:
            yield log['data']
        start_block = to_block + 1


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
