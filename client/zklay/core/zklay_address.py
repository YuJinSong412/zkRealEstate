# Copyright (c) 2021-2021 Zkrypto Inc.
#
# SPDX-License-Identifier: LGPL-3.0+

from __future__ import annotations
from zklay.core.context import ClientConfig
from zklay.core.constants import SUBGROUP_ORDER
from zklay.core.montgomery_curve import base_point_mult
from zklay.core.utils import random_field_element
from zklay.core.hash import Hash
import json
from typing import Dict, Any, List


class ZklayAddressPub:
    """
    Public zklayAddress.  upk = (addr, pk_own, pk_enc). addr = H(pk_own, pk_enc). pk_own : binding key, pk_enc : public key
    """

    def __init__(self, addr: int, pk_own: int, pk_enc: int):
        self.addr: int = addr
        self.pk_own: int = pk_own
        self.pk_enc: int = pk_enc

    def __str__(self) -> str:
        """
        Write the address as "<ownership-key-hex>:<ownership-key-hex>:<encryption_key_hex>:<encryption_key_hex>".
        (Technically the ":" is not required, since the first key is written
        with fixed length, but a separator provides some limited sanity
        checking).
        """
        return f"{self.addr}:{self.pk_own}:{self.pk_enc}"

    def to_json(self) -> str:
        return json.dumps(self._to_json_dict())

    def _to_json_dict(self) -> Dict[str, Any]:
        return {
            "addr": self.addr,
            "pk_own": self.pk_own,
            "pk_enc": self.pk_enc
        }

    def to_list(self) -> List[int]:
        return [self.addr, self.pk_own, self.pk_enc]

    def _from_json_dict(key_dict: Dict[str, Any]) -> ZklayAddressPub:
        addr = key_dict["addr"]
        pk_own = key_dict["pk_own"]
        pk_enc = key_dict["pk_enc"]
        return ZklayAddressPub(addr, pk_own, pk_enc)

    @staticmethod
    def parse(key_hex: str) -> ZklayAddressPub:
        owner_enc = key_hex.split(":")
        if len(owner_enc) != 3:
            raise Exception("invalid JoinSplitPublicKey format")
        addr = int(owner_enc[0])
        pk_own = int(owner_enc[1])
        pk_enc = int(owner_enc[2])
        return ZklayAddressPub(addr, pk_own, pk_enc)

    @staticmethod
    def from_json(key_json: str) -> ZklayAddressPub:
        return ZklayAddressPub._from_json_dict(json.loads(key_json))


class ZklayAddressPriv:
    """
    Secret zklayAddress. usk: sk_own = sk_enc = k
    """

    def __init__(self, sk: int):
        self.usk: int = sk

    def to_json(self) -> str:
        return json.dumps(self._to_json_dict())

    @staticmethod
    def from_json(key_json: str) -> ZklayAddressPriv:
        return ZklayAddressPriv._from_json_dict(json.loads(key_json))

    def _to_json_dict(self) -> Dict[str, Any]:
        return {
            "usk": self.usk,
        }

    @staticmethod
    def _from_json_dict(key_dict: Dict[str, Any]) -> ZklayAddressPriv:
        return ZklayAddressPriv(int(key_dict["usk"]))


class ZklayAddress:
    """
    Secret and public keys for both ownership and encryption (referrred to as
    "zklayAddress" in the paper).
    """

    def __init__(
            self,
            usk: int,
            addr: int,
            pk_own: int,
            pk_enc: int):
        self.upk = ZklayAddressPub(addr, pk_own, pk_enc)
        self.usk = ZklayAddressPriv(usk)

    def to_json(self) -> str:
        return json.dumps(self._to_json_dict())

    def _to_json_dict(self) -> Dict[str, Any]:
        return {
            "upk": self.upk.to_json(),
            "usk": self.usk.to_json(),
        }

    def _from_json_dict(key_dict: Dict[str, Any]) -> ZklayAddress:
        return ZklayAddress(ZklayAddressPriv._from_json_dict(key_dict["usk"]), ZklayAddressPub._from_json_dict(key_dict["upk"]))

    @staticmethod
    def from_secret_public(
            js_secret: ZklayAddressPriv,
            js_public: ZklayAddressPub) -> ZklayAddress:
        return ZklayAddress(
            js_secret.usk, js_public.addr, js_public.pk_own, js_public.pk_enc)

    @staticmethod
    def generate_keypair(client_ctx: ClientConfig) -> ZklayAddress:
        sk = random_field_element(SUBGROUP_ORDER)    # sk_own = sk_enc = k
        pk_enc = base_point_mult(client_ctx, sk)
        hash = Hash(client_ctx)
        pk_own = hash.hash(sk)
        addr = hash.hash(pk_own, pk_enc)
        return ZklayAddress(
            sk,
            addr,
            pk_own,
            pk_enc)
