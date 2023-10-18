#!/usr/bin/env python3

# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
# Copyright (c) 2021-2021 Zkrypto Inc
# SPDX-License-Identifier: LGPL-3.0+

from __future__ import annotations
from abc import abstractmethod
from typing import Tuple, Any, Dict, List
import json
from Library.zklay_address import ZklayAddressPub
from Library.context import ClientConfig
from Library.constants import SUBGROUP_ORDER
from Library.montgomery_curve import CurveParameters, multscalar, base_point_mult
from Library.utils import random_field_element
from Library.zklay_audit_address import ZklayAuditAddressPub
from Hash.hash import Hash

class EncryptionSystem:
    def __init__(
        self,
        client_ctx: ClientConfig,
        private_key: int
    ) -> None:
        self.client_ctx = client_ctx
        self.hash = Hash(client_ctx)
        self.private_key = private_key

    @abstractmethod
    def encrypt(self, *key: Any, message: Any):
        pass

    @abstractmethod
    def decrypt(self, *key: Any, ciphertext: Any):
        pass


class SymmetricKeyEncryptionSystem(EncryptionSystem):
    def __init__(
        self,
        client_ctx: ClientConfig,
        private_key: int
    ) -> None:
        super().__init__(client_ctx, private_key)
        self.field_prime = CurveParameters(self.client_ctx).field_prime

    def encrypt(self, message: int) -> S_CT:
        r = random_field_element(self.field_prime)
        ct = (message + self.hash.hash(self.private_key, r)) % self.field_prime

        return S_CT(r, ct)

    def decrypt(self, s_ct: S_CT) -> int:
        return (s_ct.ct - self.hash.hash(self.private_key, s_ct.r)) % self.field_prime


class PublicKeyEncryptionSystem(EncryptionSystem):
    def __init__(
        self,
        client_ctx: ClientConfig,
        private_key: int
    ) -> None:
        super().__init__(client_ctx, private_key)
        self.field_prime = CurveParameters(self.client_ctx).field_prime

    def encrypt(
            self,
            apk: ZklayAuditAddressPub,
            upk: ZklayAddressPub,
            *message: Any) -> Tuple[P_CT, int, int]:
        r = random_field_element(SUBGROUP_ORDER)
        k = random_field_element(self.field_prime)
        c_0 = base_point_mult(self.client_ctx, r)
        c_1 = (k * multscalar(self.client_ctx, upk.pk_enc, r)) % self.field_prime
        c_2 = (k * multscalar(self.client_ctx, apk.apk, r)) % self.field_prime
        c_3 = list()
        for idx, msg in enumerate(message):
            c_3.append(str((msg + self.hash.hash(k + idx)) % self.field_prime))

        return P_CT(
            c_0=c_0,
            c_1=c_1,
            c_2=c_2,
            c_3=c_3
        ), r, k

    def decrypt(self, p_ct: P_CT, audit=False):
        denom = multscalar(self.client_ctx, p_ct.c_0, self.private_key)
        denom = pow(denom, -1, self.field_prime)
        encrypted_key = p_ct.c_1
        if audit:
            encrypted_key = p_ct.c_2

        key = (encrypted_key * denom) % self.field_prime
        res = list()
        for idx, ct in enumerate(p_ct.c_3):
            ct = ct if isinstance(ct, int) else int(ct)
            res.append((ct - self.hash.hash(key + idx)) % self.field_prime)
        return res


class S_CT:
    """
    S_CT :: Symmetric-key encryption ciphertext class
    A ciphertext consists of two elements as follows
    (r, ct)
    """

    def __init__(self,
                 r: int,
                 ct: int) -> None:
        self.r = r
        self.ct = ct

    def to_json(self) -> str:
        return json.dumps(self._to_json_dict())

    def _to_json_dict(self) -> Dict[str, Any]:
        return {
            "r": self.r,
            "ct": self.ct
        }

    @staticmethod
    def from_json(data_json: str) -> S_CT:
        return S_CT._from_json_dict(json.loads(data_json))

    @staticmethod
    def _from_json_dict(data_dict: Dict[str, Any]) -> S_CT:
        return S_CT(
            r=data_dict["r"],
            ct=data_dict["ct"]
        )

    def to_list(self) -> List[int]:
        return [str(self.r), str(self.ct)]

    def to_list_hex(self) -> List[str]:
        return [hex(self.r)[2:], hex(self.ct)[2:]]

    def to_param_list(self) -> List[int]:
        return [self.r, self. ct]

    def empty(self) -> bool:
        if self.ct == 0 and self.r == 0:
            return True
        else:
            return False


class P_CT:
    """
    P_CT :: Public key encryption ciphertext class
    A ciphertext consists of four elements
    (c0, c1, c2, c3)
    """

    def __init__(self,
                 c_0: int,
                 c_1: int,
                 c_2: int,
                 c_3: List[int]) -> None:
        self.c_0 = c_0
        self.c_1 = c_1
        self.c_2 = c_2
        self.c_3 = c_3

    def to_json(self) -> str:
        return json.dumps(self._to_json_dict())

    def _to_json_dict(self) -> Dict[str, Any]:
        return {
            "c_0": self.c_0,
            "c_1": self.c_1,
            "c_2": self.c_2,
            "c_3": self.c_3
        }

    @staticmethod
    def from_json(data_json: str) -> P_CT:
        return P_CT._from_json_dict(json.loads(data_json))

    @staticmethod
    def _from_json_dict(data_dict: Dict[str, Any]) -> P_CT:
        return P_CT(
            c_0=data_dict["c_0"],
            c_1=data_dict["c_1"],
            c_2=data_dict["c_2"],
            c_3=data_dict["c_3"])

    def to_list(self) -> List[Any]:
        return [str(self.c_0), str(self.c_1), str(self.c_2), self.c_3]

    def to_param_list(self) -> List[Any]:
        res = list(map(int, self.c_3))
        return [self.c_0, self.c_1, self.c_2] + res
