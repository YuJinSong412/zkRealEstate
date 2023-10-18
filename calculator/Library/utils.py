#!/usr/bin/env python3

# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
# Copyright (c) 2021-2021 Zkrypto Inc
# SPDX-License-Identifier: LGPL-3.0+

# Parse the arguments given to the script

from __future__ import annotations
from Library.cli_constants import INSTANCE_FILE_DEFAULT, WALLET_DIR_DEFAULT, TOKEN_INSTANCE_FILE_DEFAULT, ZKLAY_SECRET_ADDRESS_FILE_DEFAULT, ZKLAY_AUDIT_SECRET_ADDRESS_FILE_DEFAULT, ETH_NETWORK_DEFAULT
from Library.context import ClientConfig
import Library.constants as constants
import Library.errors as errors
import argparse
import sys
import json
import os
import secrets
from os.path import join, dirname, normpath, exists
import eth_abi
import eth_keys  # type: ignore
from web3 import Web3, HTTPProvider  # type: ignore
from typing import Sequence, List, Tuple, Union, Iterable, Any, Optional, cast, Dict

# jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJwZXJtaXNzaW9ucyI6WyJldGg6KiIsIm5ldDoqIiwid2ViMzoqIl0sImV4cCI6MTY2MzI5MjQ1Mn0.JzKEQ5JLwDYq8MEAHs7dyVshQMEVqKknv3MXd9bdDNZM_PY88KNMMiP0vYaM9TQxsVRf52IFOzfKfLjf0BpHV7obnR_c8lvHcMUK5_yk6LlMRr-Sa3pzn9aNz5s2bZ8RRa2F7urRXVZ0yNPme1YD2y7Vqh9H_TYqW5hXoYXyedJ4S9BNVuY8beJaob-ZlO8UYjPi330i6G7Redcf4Mk-Yby80GMWVFzLBdIjdm2Z5DPSEm8CLM3jhn436aDsMES6KPENAfYHqTJydSRj9lwLmyIS_q07gEbXXG7YfGB2_6Td-1u2pYY0y0bfooVU-J3lZp-v8KHHZm5TzcTv9wT4hg"


# Some Ethereum node implementations can cause a timeout if the contract
# execution takes too long. We expect the contract to complete in under 30s on
# most machines, but allow 1 min.
WEB3_HTTP_PROVIDER_TIMEOUT_SEC = 60


def open_web3(
        url: str,
        certificate: Optional[str] = None,
        insecure: bool = False) -> Any:
    """
    Create a Web3 context from an http URL.
    """
    if certificate and not exists(certificate):
        raise FileNotFoundError(f"certificate file not found: {certificate}")
    assert not certificate or exists(certificate)
    request_verify: Union[str, bool, None] = False if insecure else certificate
    request_kwargs = {
        'timeout': WEB3_HTTP_PROVIDER_TIMEOUT_SEC,
        'verify': request_verify
    }
    # 'headers': {
    #         'Authorization': 'Bearer '+ jwt
    # }

    return Web3(HTTPProvider(url, request_kwargs=request_kwargs))


class EtherValue:
    """
    Representation of some amount of Ether (or any token) in terms of Wei.
    Disambiguates Ether values from other units such as zklay_units.
    """

    def __init__(self, val: Union[str, int, float], units: str = 'ether'):
        self.wei = Web3.toWei(val, units)

    def __str__(self) -> str:
        return str(self.wei)

    def __add__(self, other: EtherValue) -> EtherValue:
        return EtherValue(self.wei + other.wei, 'wei')

    def __sub__(self, other: EtherValue) -> EtherValue:
        return EtherValue(self.wei - other.wei, 'wei')

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, EtherValue):
            return False
        return self.wei == other.wei

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def __lt__(self, other: EtherValue) -> bool:
        return self.wei < other.wei

    def __le__(self, other: EtherValue) -> bool:
        return self.wei <= other.wei

    def __gt__(self, other: EtherValue) -> bool:
        return self.wei > other.wei

    def __ge__(self, other: EtherValue) -> bool:
        return self.wei >= other.wei

    def __bool__(self) -> bool:
        return int(self.wei) != 0

    def ether(self) -> str:
        return str(Web3.fromWei(self.wei, 'ether'))


def encode_single(type_name: str, data: Any) -> bytes:
    """
    Typed wrapper around eth_abi.encode_single
    """
    return eth_abi.encode_single(type_name, data)  # type: ignore


def encode_abi(type_names: List[str], data: List[Any]) -> bytes:
    """
    Typed wrapper around eth_abi.encode_abi
    """
    return eth_abi.encode_abi(type_names, data)  # type: ignore


def eth_address_to_bytes(eth_addr: str) -> bytes:
    """
    Binary encoding of ethereum address to 20 bytes
    """
    # Strip the leading '0x' and hex-decode.
    assert len(eth_addr) == 42
    assert eth_addr.startswith("0x")
    return bytes.fromhex(eth_addr[2:])


def eth_address_to_bytes32(eth_addr: str) -> bytes:
    """
    Binary encoding of ethereum address to 32 bytes
    """
    return extend_32bytes(eth_address_to_bytes(eth_addr))


def eth_uint256_to_int(eth_uint256: str) -> int:
    assert isinstance(eth_uint256, str)
    assert eth_uint256.startswith("0x")
    return int.from_bytes(
        bytes.fromhex(hex_extend_32bytes(eth_uint256[2:])),
        byteorder='big')


def eth_address_from_private_key(eth_private_key: bytes) -> str:
    pk = eth_keys.keys.PrivateKey(eth_private_key)
    return pk.public_key.to_address()


def int_and_bytelen_from_hex(value_hex: str) -> Tuple[int, int]:
    """
    Decode prefixed / non-prefixed hex string and extract the length in bytes
    as well as the value.
    """
    assert len(value_hex) % 2 == 0
    if value_hex.startswith("0x"):
        num_bytes = int((len(value_hex) - 2) / 2)
    else:
        num_bytes = int(len(value_hex) / 2)
    return (int(value_hex, 16), num_bytes)


def int_to_hex(value: int, num_bytes: int, prefix: Optional[bool] = True) -> str:
    """
    Create prefixed hex string enforcing a specific byte-length.
    """
    hex_value = value.to_bytes(num_bytes, byteorder='big').hex()
    if prefix:
        return "0x" + hex_value
    else:
        return hex_value


def int_list_to_hex_list(int_list: List[int], num_bytes: Optional[int] = 32, prefix: Optional[bool] = False) -> List[str]:
    return [int_to_hex(i, num_bytes, prefix) for i in int_list]


def int256_to_bytes(number: int) -> bytes:
    return number.to_bytes(32, 'big')


def int256_to_bytes_little(number: int) -> bytes:
    return number.to_bytes(32, 'little')


def bytes_to_int256(byte: bytes) -> int:
    return int.from_bytes(byte, 'big')


def int64_to_bytes(number: int) -> bytes:
    return number.to_bytes(8, 'big')


def int64_to_hex(number: int) -> str:
    return int64_to_bytes(number).hex()


def hex_digest_to_binary_string(digest: str) -> str:
    if len(digest) % 2 == 1:
        digest = "0" + digest
    return "".join(["{0:04b}".format(int(c, 16)) for c in digest])


def digest_to_binary_string(digest: bytes) -> str:
    return "".join(["{0:08b}".format(b) for b in digest])


def hex_to_uint256_list(hex_str: str) -> Iterable[int]:
    """
    Given a hex string of arbitrary size, split into uint256 ints, left padding
    with 0s.
    """
    if hex_str.startswith("0x"):
        hex_str = hex_str[2:]
    assert len(hex_str) % 2 == 0
    start_idx = 0
    next_idx = len(hex_str) - int((len(hex_str) - 1) / 64) * 64
    while next_idx <= len(hex_str):
        sub_str = hex_str[start_idx:next_idx]
        yield int(sub_str, 16)
        start_idx = next_idx
        next_idx = next_idx + 64


def hex_list_to_uint256_list(
        elements: Sequence[Union[str, List[str]]]) -> List[int]:
    """
    Given an array of hex strings, return an array of int values by converting
    each hex string to evm uint256 words, and flattening the final list.
    """
    # In reality, we need to cope with lists of lists, to handle all
    # field extension degrees for all curve coordinate types.
    # TODO: Create a new type to describe this safely.
    flat_elements = string_list_flatten(elements)
    return [i for hex_str in flat_elements for i in hex_to_uint256_list(hex_str)]


def extend_32bytes(value: bytes) -> bytes:
    """
    Pad value on the left with zeros, to make 32 bytes.
    """
    assert len(value) <= 32
    return bytes(32-len(value)) + value


def hex_extend_32bytes(element: str) -> str:
    """
    Extend a hex string to represent 32 bytes
    """
    res = str(element)
    if len(res) % 2 != 0:
        res = "0" + res
    return extend_32bytes(bytes.fromhex(res)).hex()


def random_field_element(modulo: int):
    return secrets.randbits(modulo.bit_length()) % modulo


def to_zklay_units(value: EtherValue) -> int:
    """
    Convert a quantity of ether / token to Zklay units
    """
    return int(value.wei / constants.ZKLAY_PUBLIC_UNIT_VALUE)


def from_zklay_units(zklay_units: int) -> EtherValue:
    """
    Convert a quantity of ether / token to Zklay units
    """
    return EtherValue(zklay_units * constants.ZKLAY_PUBLIC_UNIT_VALUE, "wei")


def parse_zksnark_arg() -> str:
    """
    Parse the zksnark argument and return its value
    """
    parser = argparse.ArgumentParser(
        description="Testing Zklay transactions using the specified zkSNARK " +
        "('GROTH16' or 'PGHR13').\nNote that the zkSNARK must match the one " +
        "used on the prover server.")
    parser.add_argument("zksnark", help="Set the zkSNARK to use")
    args = parser.parse_args()
    if args.zksnark not in constants.VALID_ZKSNARKS:
        return sys.exit(errors.SNARK_NOT_SUPPORTED)
    return args.zksnark


def get_zklay_client_dir() -> str:
    return os.environ.get(
        'ZKLAY-CLIENT',
        join(get_zklay_dir(), "client"))


def get_zklay_config_file_path() -> str:
    return get_zklay_client_dir() + "/prover-config"


def load_default_config() -> ClientConfig:
    return ClientConfig(
        env=ETH_NETWORK_DEFAULT,
        instance_file=INSTANCE_FILE_DEFAULT,
        token_instance_file=TOKEN_INSTANCE_FILE_DEFAULT,
        address_file=ZKLAY_SECRET_ADDRESS_FILE_DEFAULT,
        audit_address_file=ZKLAY_AUDIT_SECRET_ADDRESS_FILE_DEFAULT,
        wallet_dir=WALLET_DIR_DEFAULT,
        depth=32,
        hash='MiMC7',
        zksnark='GROTH16',
        ec='BN256'
    )


def get_zklay_dir() -> str:
    return os.environ.get(
        'ZKLAY',
        normpath(join(dirname(__file__), "..", "..", "..")))


def get_libsnark_lib_dir() -> str:
    return os.environ.get(
        'LIBSNARK_LIB',
        join(get_zklay_dir(), "depends/libsnark-optimization/lib/"))


def get_contracts_dir() -> str:
    return os.environ.get(
        'ZKLAY_CONTRACTS_DIR',
        join(get_zklay_dir(), "zklay_contracts", "contracts"))


def string_list_flatten(str_list: Sequence[Union[str, List[str]]]) -> List[str]:
    """
    Flatten a list containing strings or lists of strings.
    """
    if any(isinstance(el, (list, tuple)) for el in str_list):
        strs: List[str] = []
        for el in str_list:
            if isinstance(el, (list, tuple)):
                strs.extend(el)
            else:
                strs.append(cast(str, el))
        return strs

    return cast(List[str], str_list)


def message_to_bytes(message_list: Any) -> bytes:
    # message_list: Union[List[str], List[Union[int, str, List[str]]]]) -> bytes:
    """
    Encode a list of variables, or list of lists of variables into a byte
    vector
    """

    messages = string_list_flatten(message_list)

    data_bytes = bytearray()
    for m in messages:
        # For each element
        m_hex = m

        # Convert it into a hex
        if isinstance(m, int):
            m_hex = "{0:0>4X}".format(m)
        elif isinstance(m, str) and (m[1] == "x"):
            m_hex = m[2:]

        # [SANITY CHECK] Make sure the hex is 32 byte long
        m_hex = hex_extend_32bytes(m_hex)

        # Encode the hex into a byte array and append it to result
        data_bytes += encode_single("bytes32", bytes.fromhex(m_hex))

    return data_bytes


def short_commitment(cm: bytes) -> str:
    """
    Summary of the commitment value, in some standard format.
    """
    cm = int256_to_bytes(cm) if isinstance(cm, int) else cm
    return cm[0:4].hex()


def int_to_bit_concat(*num: bytes) -> Tuple[int, int]:
    res = ""
    reverse_num = reversed(list(num))
    for n in reverse_num:
        res += f'{int.from_bytes(n,"big"):0254b}'
    return int(res, 2), len(num)


def modular_sqrt(a, p):
    """ Find a quadratic residue (mod p) of 'a'. p
        must be an odd prime.

        Solve the congruence of the form:
            x^2 = a (mod p)
        And returns x. Note that p - x is also a root.

        0 is returned is no square root exists for
        these a and p.

        The Tonelli-Shanks algorithm is used (except
        for some simple cases in which the solution
        is known from an identity). This algorithm
        runs in polynomial time (unless the
        generalized Riemann hypothesis is false).
    """
    # Simple cases
    #
    if legendre_symbol(a, p) != 1:
        return 0
    elif a == 0:
        return 0
    elif p == 2:
        return 0
    elif p % 4 == 3:
        return pow(a, (p + 1) // 4, p)

    # Partition p-1 to s * 2^e for an odd s (i.e.
    # reduce all the powers of 2 from p-1)
    #
    s = p - 1
    e = 0
    while s % 2 == 0:
        s //= 2
        e += 1

    # Find some 'n' with a legendre symbol n|p = -1.
    # Shouldn't take long.
    #
    n = 2
    while legendre_symbol(n, p) != -1:
        n += 1

    # Here be dragons!
    # Read the paper "Square roots from 1; 24, 51,
    # 10 to Dan Shanks" by Ezra Brown for more
    # information
    #

    # x is a guess of the square root that gets better
    # with each iteration.
    # b is the "fudge factor" - by how much we're off
    # with the guess. The invariant x^2 = ab (mod p)
    # is maintained throughout the loop.
    # g is used for successive powers of n to update
    # both a and b
    # r is the exponent - decreases with each update
    #
    x = pow(a, (s + 1) // 2, p)
    b = pow(a, s, p)
    g = pow(n, s, p)
    r = e

    while True:
        t = b
        m = 0
        for m in range(r):
            if t == 1:
                break
            t = pow(t, 2, p)

        if m == 0:
            return x

        gs = pow(g, 2 ** (r - m - 1), p)
        g = (gs * gs) % p
        x = (x * gs) % p
        b = (b * g) % p
        r = m


def legendre_symbol(a, p):
    """ Compute the Legendre symbol a|p using
        Euler's criterion. p is a prime, a is
        relatively prime to p (if p divides
        a, then a|p = 0)

        Returns 1 if a has a square root modulo
        p, -1 otherwise.
    """
    ls = pow(a, (p - 1) // 2, p)
    return -1 if ls == p - 1 else ls


class Pocket:
    def __init__(self,
                 v_priv: EtherValue,
                 v_in: EtherValue,
                 v_out: EtherValue) -> None:
        self.v_priv = v_priv
        self.v_in = v_in
        self.v_out = v_out

    def to_json(self) -> str:
        return json.dumps(self._to_json_dict())

    def _to_json_dict(self) -> Dict[str, Any]:
        return {
            "v_priv": self.v_priv.ether(),
            "v_in": self.v_in.ether(),
            "v_out": self.v_out.ether()
        }

    @staticmethod
    def from_json(data_json: str) -> Pocket:
        return Pocket._from_json_dict(json.loads(data_json))

    @staticmethod
    def _from_json_dict(data_dict: Dict[str, Any]) -> Pocket:
        return Pocket(
            v_priv=data_dict["v_priv"],
            v_in=data_dict["v_out"],
            v_out=data_dict["v_out"],
        )
