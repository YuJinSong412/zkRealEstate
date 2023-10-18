# Copyright (c) 2021-2021 Zkrypto Inc
#
# SPDX-License-Identifier: LGPL-3.0+

from __future__ import annotations
from Library.constants import SUBGROUP_ORDER
from Library.montgomery_curve import base_point_mult
from Library.utils import random_field_element
from Library.context import ClientConfig
import json
from typing import Dict, Any


class ZklayAuditAddressPub:
    def __init__(self, apk: int):
        self.apk = apk

    def to_json(self) -> str:
        return json.dumps((self._to_json_dict()))

    def _to_json_dict(self) -> Dict[str, Any]:
        return {
            "apk": self.apk
        }

    @staticmethod
    def from_json(key_json: str) -> ZklayAuditAddressPub:
        return ZklayAuditAddressPub._from_json_dict(json.loads(key_json))

    @staticmethod
    def _from_json_dict(key_dict: Dict[str, Any]) -> ZklayAuditAddressPub:
        return ZklayAuditAddressPub(
            apk=int(key_dict["apk"]))

    @staticmethod
    def parse(key: str) -> ZklayAuditAddressPub:
        dict_key = json.loads(key)

        return ZklayAuditAddressPub(int(dict_key["apk"]))


class ZklayAuditAddressPriv:
    def __init__(self, ask: int):
        self.ask = ask

    def to_json(self) -> str:
        return json.dumps((self._to_json_dict()))

    def _to_json_dict(self) -> Dict[str, Any]:
        return {
            "ask": self.ask
        }

    @staticmethod
    def from_json(key_json: str) -> ZklayAuditAddressPriv:
        return ZklayAuditAddressPriv._from_json_dict(json.loads(key_json))

    @staticmethod
    def _from_json_dict(key_dict: Dict[str, Any]) -> ZklayAuditAddressPriv:
        return ZklayAuditAddressPriv(
            ask=int(key_dict["ask"]))


class ZklayAuditAddress:
    def __init__(
            self,
            apk: ZklayAuditAddressPub,
            ask: ZklayAuditAddressPriv):
        self.apk = apk
        self.ask = ask

    @staticmethod
    def from_secret_public(
            js_public: ZklayAuditAddressPub,
            js_secret: ZklayAuditAddressPriv) -> ZklayAuditAddress:
        return ZklayAuditAddress(js_public, js_secret)

    @staticmethod
    def generate_keypair(client_ctx: ClientConfig) -> ZklayAuditAddress:
        ask = random_field_element(SUBGROUP_ORDER)
        apk = base_point_mult(client_ctx, ask)

        auditor_pk = ZklayAuditAddressPub(apk)
        auditor_sk = ZklayAuditAddressPriv(ask)

        return ZklayAuditAddress(auditor_pk, auditor_sk)
