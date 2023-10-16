# Copyright (c) 2021-2021 Zkrypto Inc

from __future__ import annotations
from typing import Dict, List, Optional, Tuple, Iterator, cast, Any
from unittest import TestCase
from zklay.cli.constants import ACC_DATA_FILE
from zklay.core.zklay_encryption import Hash
from zklay.core.pairing import G1Point
from zklay.core.accumulator import PersistentAccumulator



class TestAccumulator(TestCase):
    def test_accumulator(self) -> None:

        def int_to_bytes(num : int) -> bytes :
            return num.to_bytes(256,'big')

        def hex_to_int256(hex_str : str) :
            if hex_str.startswith("0x") :
                hex_str = hex_str[2:]
            assert len(hex_str) % 2 == 0
            
            return int(hex_str,16)

        filename = ACC_DATA_FILE
        ACC = PersistentAccumulator.open(filename)    
        ACC.save()
        test_acc = PersistentAccumulator.open(filename)
        print(test_acc.to_json())
        test_acc.add([1,2,3,4,5])
        test_acc.add(6)
        test_acc.accumulate()
        print(test_acc.to_json())

        test_values = [
            G1Point(
                "0x2af03b0046e15e8f24cdf4515d07cdbc5546ccd73fef162d453c55c6a635f6ee",
                "0x1a7710fe73530a5d4a81c00725656b73dbac818e544462d2227d09b269813d90")
            ,
            G1Point(
               "0x2825a2f1be85b53051e3affe3f3d3f68ebc52e7c3adc18d6e869630b67fabf3d",
                "0x094d9300fbef14f29e7c0de15ac229a719cae308cd100f9f06bc540ad1369bec")
            ,
            G1Point(
                "0x292b1333bfd842684eda6bb553d055ef992e2f40fb296e01753e15df3b22c69e",
                "0x187b68654c41f2723dee3c028c1f06d36de5448a02857365bb1acc9c90f2d04a")
        ]

        res = test_acc.compute([1,2,3],test_values)
        print(res)
        print(test_acc.to_json())
        """
        W = res[0]
        C = res[1]
        k = res[2]
        Hash = res[4]
        (W^k/ACC^h)
        """
        ACC = test_acc.acc_data.ACC
        up = pow(res[0],res[2],test_acc.N)
        down = pow(ACC,res[3],test_acc.N)

        res1 = Hash(
            int_to_bytes(res[0]),
            int_to_bytes(hex_to_int256(res[1].x_coord)),
            int_to_bytes(hex_to_int256(res[1].y_coord)),
            up/down    
        )

        if res[4] == res1 :
            print("PASS")
        else :
            print("FAIL")

        test_acc.save()

if __name__ == "__main__" :
    TestAccumulator().test_accumulator()