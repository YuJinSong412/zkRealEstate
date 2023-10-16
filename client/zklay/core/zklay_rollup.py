from __future__ import annotations
from zklay.core.zklay_snark import zklay_statement, Proof
from typing import Optional
import json


class RollupParameters:
    def __init__(self, stmt: zklay_statement, proof: Proof) -> None:
       self.rollup_param_dict = RollupParameters.convert(stmt,proof)

    @staticmethod
    def convert(stmt: zklay_statement, proof: Proof):
        return {
            "rt": stmt.str_value_list[7],
            "sn": stmt.str_value_list[8],
            "addr": stmt.str_value_list[3],
            "k_b": stmt.str_value_list[4],
            "k_u": stmt.str_value_list[5],
            "cm_": stmt.str_value_list[9],
            "cin": stmt.arr_value_list[0],
            "cout": stmt.arr_value_list[1],
            "CT": stmt.arr_value_list[2],
            "pv": stmt.str_value_list[10],
            "pv_": stmt.str_value_list[11],
            "G_r": stmt.str_value_list[0],
            "K_u": stmt.str_value_list[1],
            "K_a": stmt.str_value_list[2],
            "proof": proof._proof_to_json_dict()
        }


    def to_json(self) -> str:
        return json.dumps(self.rollup_param_dict,sort_keys=True,indent=4, separators = (',', ': '))

    
    def write_rollup_param(self, file: str, path:Optional[str] = None) -> None:
        if path != None:
            file = path + "/" + file
        with open(file, "w") as f:
            f.write(self.to_json())

    
