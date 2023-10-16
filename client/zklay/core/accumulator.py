# Copyright (c) 2021-2021 Zkrypto Inc.
#
# SPDX-License-Identifier: LGPL-3.0+

from __future__ import annotations
from functools import reduce
from os.path import exists
from typing import Dict, List, Optional, Tuple, Iterator, cast, Any
from zklay.core.zklay_encryption import get_value, get_EC_result
from zklay.core.utils import bytes_to_int256, int256_to_bytes
from zklay.core.mimc import MiMC7
from zklay.core.pairing import G1Point
from zklay.core.constants import DEFAULT_N
# from zklay.core.constants import JSNARK_PATH
import json,math,random,os

PRIME_VALUES = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 
        73,	79,	83,	89,	97,	101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 
        179, 181, 191, 193, 197, 199, 211, 223,	227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281,
        283, 293, 307, 311,	313, 317, 331, 337,	347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 
        419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479,	487, 491, 499, 503,	509, 521, 523, 541,
        547, 557, 563, 569, 571, 577, 587, 593,	599, 601, 607, 613, 617, 619, 631, 641,	643, 647, 653, 659, 
        661, 673, 677, 683, 691, 701, 709, 719, 727,
        733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859,
        863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997, 1009,
        1013, 1019, 1021, 1031, 1033, 1039, 1049, 1051, 1061, 1063, 1069, 1087, 1091, 1093, 1097, 1103, 1109, 1117, 1123, 1129, 
        1151, 1153, 1163, 1171, 1181, 1187, 1193, 1201, 1213, 1217, 1223, 1229, 1231, 1237, 1249, 1259, 1277, 1279, 1283, 1289,
        1291, 1297, 1301, 1303, 1307, 1319, 1321, 1327, 1361, 1367, 1373, 1381, 1399, 1409, 1423, 1427, 1429, 1433, 1439, 1447,
        1451, 1453, 1459, 1471, 1481, 1483, 1487, 1489, 1493, 1499, 1511, 1523, 1531, 1543, 1549, 1553, 1559, 1567, 1571, 1579, 
        1583, 1597, 1601, 1607, 1609, 1613, 1619, 1621]

ONE : int = 1
ZERO : int = 0

def Hash(*input : bytes) -> int:
    def bigint_to_bytes(input) :
        return input.to_bytes(256,"big")
    data_list = list(input)
    length = len(data_list)
    for i,data in enumerate(data_list) :
        if isinstance(data, int) :
            data_list[i] = bigint_to_bytes(data)
    mimc7 = MiMC7()
    assert length > 0, "The input of hash must be larger than 0"
    if length == 1 :
        return bytes_to_int256(mimc7.hash(data_list[0], data_list[0]))
    else :
        res = mimc7.hash(data_list[0],data_list[1])
        for i in range(0,len(data_list)-2) :
            res = mimc7.hash(res,data_list[i+2])
        return bytes_to_int256(res)

def nBitRandom(n):
    return random.randrange(2**(n-1)+1, 2**n - 1)

def getLowLevelPrime(n):
    while True:
        # Obtain a random number
        pc = nBitRandom(n) 
  
         # Test divisibility by pre-generated 
         # primes
        for divisor in PRIME_VALUES:
            if pc % divisor == 0 and divisor**2 <= pc:
                break
        else: return pc

def isMillerRabinPassed(mrc):
    maxDivisionsByTwo = 0
    ec = mrc-1
    while ec % 2 == 0:
        ec >>= 1
        maxDivisionsByTwo += 1
    assert(2**maxDivisionsByTwo * ec == mrc-1)
    def trialComposite(round_tester):
        if pow(round_tester, ec, mrc) == 1:
            return False
        for i in range(maxDivisionsByTwo):
            if pow(round_tester, 2**i * ec, mrc) == mrc-1:
                return False
        return True
    # Set number of trials here
    numberOfRabinTrials = 20 
    for i in range(numberOfRabinTrials):
        round_tester = random.randrange(2, mrc)
        if trialComposite(round_tester):
            return False
    return True

def get_nbit_prime(N : int) :
    while True :
        prime_can = getLowLevelPrime(N)
        if not isMillerRabinPassed(prime_can):
            continue
        else:
            break
    return prime_can

def multiply(arr : List[int]) -> int:
        return reduce(lambda x, y: x * y, arr)

def int_to_bytes(num : int) -> bytes :
            return num.to_bytes(256,'big')
        
class AccumulatorProof:
    def __init__(
        self,
        W_hat : int,
        C_sr : G1Point,
        k : int,
        h : int
        ):
        self.W_hat = W_hat
        self.C_sr = C_sr
        self.k = k
        self.h = h

    @staticmethod
    def from_json_dict(json_dict : Dict[str,Any]) -> AccumulatorProof :
        W_hat = cast(int,json_dict["W_hat"])
        C_sr = cast(G1Point, json_dict["C_sr"])
        k = cast(int, json_dict["k"])
        h = cast(int, json_dict["h"])

        return AccumulatorProof(
            W_hat,
            C_sr,
            k,
            h
        )
    
    def _to_json_dict(self) -> Dict[str,Any] :
        return {
            "W_hat" : self.W_hat,
            "C_sr" : str(self.C_sr),
            "k" : self.k,
            "h" : self.h
        }

    def to_json(self) -> str:
        return json.dumps(self._to_json_dict())
    



class AccumulatorData :
    def __init__(
        self,
        ACC : int,
        cm_list : List[int] ):
        self.ACC = ACC
        self.cm_list = cm_list

    @staticmethod
    def from_json_dict(json_dict : Dict[str,Any]) -> AccumulatorData :
        ACC = cast(int,json_dict["ACC"])
        cm_list = (cast(List[int], json_dict["cm_list"]))

        return AccumulatorData(
            ACC = ACC,
            cm_list = cm_list
        )
    
    def to_json_dict(self) -> Dict[str,Any] :
        return {
            "ACC" : self.ACC,
            "cm_list" : self.cm_list
        }


class Accumulator :
    def __init__(
        self,
        acc_data : AccumulatorData,
        W : int,
        N : int,
        SEC_LEV : int ) -> None:
        self.acc_data = acc_data
        self.N = N
        self.W = W
        self.SEC_LEV = SEC_LEV
        self.prime_group = PRIME_VALUES[:self.SEC_LEV]

    @staticmethod
    def _init_acc_data(
        N,
        W,
        SEC_LEV
    ) -> AccumulatorData :
        # N = DEFAULT_N
        # W = get_nbit_prime(N.bit_length())
        SEC_LEV = SEC_LEV or 256
        prime_group = PRIME_VALUES[:SEC_LEV]
        ACC = W
        for i in range(SEC_LEV) :
            ACC = pow(ACC,prime_group[i],N)

        return AccumulatorData(
            ACC = ACC,
            cm_list = list())

    @staticmethod
    def init_acc(SEC_LEV : Optional[int] = None) -> Accumulator :
        N = DEFAULT_N
        # W = get_nbit_prime(N.bit_length())
        W = 2
        SEC_LEV = SEC_LEV or 256
        acc_data = Accumulator._init_acc_data(N,W,SEC_LEV)

        return Accumulator(
            acc_data= acc_data,
            W = W,
            N = N,
            SEC_LEV= SEC_LEV
        )

    @staticmethod
    def from_json_dict(json_dict : Dict[str,Any]) -> Accumulator :
        acc_data = json_dict["acc_data"]
        W = cast(int, json_dict["W"])
        N = cast(int, json_dict["N"])
        SEC_LEV = cast(int,json_dict["SEC_LEV"])
    
        return Accumulator(
            acc_data = acc_data,
            W = W,
            N = N,
            SEC_LEV = SEC_LEV
        )

    def _to_json_dict(self) -> Dict[str, Any]:
        return {
            "W": self.W,
            "N" : self.N,
            "SEC_LEV" : self.SEC_LEV,
            # "prime_group" : self.prime_group,
            "acc_data" : self.acc_data.to_json_dict(),    
        }

    def to_json(self) -> str:
        return json.dumps(self._to_json_dict())

    def add(self,
        users : Any) :
        if isinstance(users,int) :
            self.acc_data.cm_list.append(users)
        elif isinstance(users,list) :
            self.acc_data.cm_list.extend(users)
        # if isinstance(users,int) :
        #     self.acc_data.cm_list.append(Hash(int256_to_bytes(users)))
        # elif isinstance(users,list) :
        #     for user in users:
        #         self.acc_data.cm_list.append(Hash(int256_to_bytes(user)))

    def accumulate(self) :
        exp_values = self.prime_group + self.acc_data.cm_list
        self.acc_data.ACC = self.W
        for value in exp_values :
            self.acc_data.ACC = pow(self.acc_data.ACC, value, self.N)
        # self.acc_data.ACC = self.W
        # for e in self.prime_group:
        #     self.W = pow(self.W, e, self.N)
        # for s in self.acc_data.cm_list:
        #     self.W = pow(self.W, s, self.N)
        # self.acc_data.ACC = self.W
        
    def compute(self,
        users : List[int],
        bases : List[G1Point]
    ) -> AccumulatorProof :
        # W^hat == W  // W == V
        MUL_U = multiply(users)
        MUL_S = ONE

        rand = nBitRandom(self.SEC_LEV)
        rand_bits = str(bin(rand))[2:] # 
        W_hat = self.W

        for i in range(self.SEC_LEV):
            if rand_bits[i] == str(ZERO):
                W_hat = pow(W_hat, self.prime_group[i], self.N)
            else:
                MUL_S = MUL_S * self.prime_group[i]
        
        for s in self.acc_data.cm_list:
            if s not in users:
                W_hat = pow(W_hat, s, self.N)

        length = MUL_U.bit_length() + MUL_S.bit_length() + self.SEC_LEV + 2 * len(self.prime_group)
        r = nBitRandom(length)    # sample r
        R = pow(W_hat, r, self.N)  # R <- W_u ^r

        C_sr = self._commit_IO_CRS(s = MUL_S, r =  r , u = MUL_U, Points = bases) # c <- comm(s, r ; o)

        h = Hash(
            int_to_bytes(W_hat),
            int_to_bytes(int(C_sr.x_coord)),
            int_to_bytes(int(C_sr.y_coord)),
            int_to_bytes(R))
        
        k = r + MUL_S * MUL_U * h # k = r + u* s h

        proof = AccumulatorProof(W_hat, C_sr, k, h)
        print("proof")
        print(proof.to_json())

        return proof


    def _commit_IO_CRS(
        self,
        s : int,
        r : int,
        u : int,
        Points: List[G1Point]) -> G1Point :
        """
        Compute the commitment with s, r, u
        C <- commitIOcrs ( s, r, u) 
        """
        assert len(Points) == 3

        def split_254bit(value : int) :
            FIX_LEN = 253
            if value.bit_length() > 253 :
                return [value]
            else :
                bit_str = str(bin(value))[2:]
                return [int(''.join(x),2) for x in zip(*[list(bit_str[z::FIX_LEN]) for z in range(FIX_LEN)])]

        
        S = split_254bit(s)
        R = split_254bit(r)
        U = split_254bit(u)
        EXP_LIST = [S,R,U]
        res_list = list()
        
        for point in Points :
            point.x_coord = hex_to_int256(point.x_coord)
            point.y_coord = hex_to_int256(point.y_coord)
        
        for point, exp in zip(Points,EXP_LIST) :
            for e in exp :
                res_list.append(get_mul_EC(point, e))

        C = res_list[0]
        for i in range(1,len(res_list)) :
            C = get_add_EC(C,res_list[i])
        
        return C

    def verify(self,
        proof : AccumulatorProof) -> bool:

        denom = pow(self.acc_data.ACC, -proof.h, self.N)
        num = pow(proof.W_hat, proof.k, self.N)

        ret = num * denom % self.N
        hash = Hash(
            proof.W_hat, 
            int_to_bytes(int(proof.C_sr.x_coord)),
            int_to_bytes(int(proof.C_sr.y_coord)),
            ret)
        print("hash_verify : ", hash)
        print("hash_proof  : ", proof.h)
        return hash == proof.h

def mod_inverse(x, m):
    return None

def hex_to_int256(hex_str : str) :
    if hex_str.startswith("0x") :
        hex_str = hex_str[2:]
    assert len(hex_str) % 2 == 0
    
    return int(hex_str,16)


def _to_list_bytes(list_str: List[str]) -> List[bytes]:
    return [bytes.fromhex(entry) for entry in list_str]


def _to_list_str(list_bytes: List[bytes]) -> List[str]:
    return [entry.hex() for entry in list_bytes]

class PersistentAccumulator(Accumulator) :
    def __init__(
        self,
        filename : str,
        acc_data: AccumulatorData,
        W: int,
        N: int,
        SEC_LEV: int) -> None:
        super().__init__(acc_data, W, N, SEC_LEV)
        self.filename = filename

    @staticmethod
    def open(
        filename : str) :
        if exists(filename) : 
            with open(filename, "r") as acc_f :
                ACC_json_dict = json.load(acc_f)
                ACC_DATA_json_dict = ACC_json_dict["acc_data"]
                acc = Accumulator.from_json_dict(ACC_json_dict)
                acc_data = AccumulatorData.from_json_dict(ACC_DATA_json_dict)
        else :
            acc = Accumulator.init_acc()
            acc_data = acc.acc_data
        

        return PersistentAccumulator(
            filename= filename,
            acc_data = acc_data,
            W = acc.W,
            N = acc.N,
            SEC_LEV= acc.SEC_LEV
        )
    
    def save(self) ->None :
        with open(self.filename, "w") as acc_f :
            json.dump(self._to_json_dict(),acc_f)