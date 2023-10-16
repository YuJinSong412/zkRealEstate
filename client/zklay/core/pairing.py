# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

"""
Generic pairing types and operations
"""

from __future__ import annotations
from .utils import hex_to_uint256_list, hex_list_to_uint256_list, \
    int_and_bytelen_from_hex, int_to_hex
from math import log, floor
from typing import Dict, List, Union, Any
from zklay.core.constants import CURVE_ORDER


class G1Point:
    """
    G1 Group Points. A typed tuple of strings, stored as a JSON array.
    """

    def __init__(self, x_coord: str, y_coord: str):
        self.x_coord = x_coord
        self.y_coord = y_coord

    def __str__(self) -> str:
        return str(self.to_json_list())

    def __repr__(self) -> str:
        return self.__str__()

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, G1Point):
            return False
        return (self.x_coord == other.x_coord) and (self.y_coord == other.y_coord)

    def to_json_list(self) -> List[str]:
        return [self.x_coord, self.y_coord]

    @staticmethod
    def _squared(value):
        return pow(value, value, CURVE_ORDER)

    @staticmethod
    def from_json_list(json_list: List[str]) -> G1Point:
        return G1Point(json_list[0], json_list[1])


def g1_point_to_contract_parameters(g1: G1Point) -> List[int]:
    return \
        list(hex_to_uint256_list(g1.x_coord)) + \
        list(hex_to_uint256_list(g1.y_coord))


class G2Point:
    """
    G2 Group Points. Depending on the curve, coordinates may be in the base
    (non-extension) field (i.e. simple json strings), or an extension field
    (i.e. a list of strings).
    """

    def __init__(
            self,
            x_coord: Union[str, List[str]],
            y_coord: Union[str, List[str]]):
        self.x_coord = x_coord
        self.y_coord = y_coord

    def __str__(self) -> str:
        return str(self.to_json_list())

    def __repr__(self) -> str:
        return self.__str__()

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, G2Point):
            return False
        return (self.x_coord == other.x_coord) and (self.y_coord == other.y_coord)

    def to_json_list(self) -> List[Union[str, List[str]]]:
        return [self.x_coord, self.y_coord]

    @staticmethod
    def from_json_list(json_list: List[Union[str, List[str]]]) -> G2Point:
        return G2Point(json_list[0], json_list[1])


def g2_point_to_contract_parameters(g2: G2Point) -> List[int]:
    if isinstance(g2.x_coord, str):
        assert isinstance(g2.y_coord, str)
        return \
            list(hex_to_uint256_list(g2.x_coord)) + \
            list(hex_to_uint256_list(g2.y_coord))
    return \
        hex_list_to_uint256_list(g2.x_coord) + \
        hex_list_to_uint256_list(g2.y_coord)
