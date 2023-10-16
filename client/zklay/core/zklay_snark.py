from __future__ import annotations
import ctypes
from genericpath import exists
import pathlib
from typing import Any, List, Dict, Optional
from zklay.core.constants import ZKLAY_CRS_PK, ZKLAY_CRS_VK
from zklay.core.pairing import G1Point, G2Point, \
    g1_point_to_contract_parameters,g2_point_to_contract_parameters
from zklay.core.utils import get_libsnark_lib_dir, int_list_to_hex_list
from zklay.cli.debugger import print_wrapper
from zklay.core.zklay_audit_address import ZklayAuditAddressPub
from zklay.core.zklay_encryption import S_CT, P_CT
from zklay.core.zklay_address import \
    ZklayAddressPub, ZklayAddressPriv
from zklay.core.utils import EtherValue
from zklay.core.context import ClientConfig
from os.path import exists
from abc import (ABC, abstractmethod)
import json, platform

PROOF_SYSTEM_GG = 1
PROOF_SYSTEM_SE = 2
ZKLAY_SERIAL = 3

LINUX = "linux"
DARWIN = "darwin"
ZKLAY = "ZKlay"
doc_loc = str(pathlib.Path().absolute()) + "/"


def s2c (string) :
	b_string = string.encode('utf-8')
	return ctypes.c_char_p(b_string)


def load_libsnark_library() -> Any:
    libsnark_lib_path = get_libsnark_lib_dir()
    arch = platform.system().lower()
    machine = platform.machine().lower()
    platform_name = arch + '_' + 'release'
    dll_name = "libSnark.so" if arch == LINUX else "libSnark.dylib"
    dll_path = platform_name + "/lib/" + dll_name
    lib_path = libsnark_lib_path + dll_path

    return ctypes.CDLL(lib_path)


class snark : 
    def __init__(self, client_ctx: ClientConfig) -> None:
        self.client_ctx = client_ctx
        self.__libsnark = load_libsnark_library()
        self.__libsnark.getLastFunctionMsg.restype = ctypes.c_char_p 
        self.__libsnark.serializeProof.restype = ctypes.c_char_p 
        self.__libsnark.serializeVerifyKey.restype = ctypes.c_char_p

    def _createCircuitArguments(self):
        args = [self.client_ctx.depth, self.client_ctx.hash]
        args_len = len(args)

        array_type = (ctypes.c_char_p * args_len)
        arg_list = []
        for key, item in enumerate(args):
            arg_list.append([key, item.encode()])
        return arg_list
    

    @print_wrapper(0)
    def Gen(self, context_id : int):
        args = self._createCircuitArguments()
        self.__libsnark.assignCircuitArgument(context_id, s2c("treeHeight"), args[0][1])
        self.__libsnark.assignCircuitArgument(context_id, s2c("hashType"), args[1][1])
        self.__libsnark.buildCircuit(context_id)
        rtn = self.__libsnark.runSetup(context_id )
        msg = self.__libsnark.getLastFunctionMsg(context_id).decode('utf-8')
        print ("RunSetup : %d , %s" % (rtn , msg) )
        self.__libsnark.writeVK(context_id, s2c(ZKLAY_CRS_VK))
        self.__libsnark.writePK(context_id, s2c(ZKLAY_CRS_PK))

    @print_wrapper(0)
    def reGen(self, context_id: int):
        args = self._createCircuitArguments()
        self.__libsnark.assignCircuitArgument(context_id, s2c("treeHeight"), args[0][1])
        self.__libsnark.assignCircuitArgument(context_id, s2c("hashType"), args[1][1])
        self.__libsnark.buildCircuit(context_id)
        self.ReadPK(context_id=context_id)

    def UpdatePrimaryInput(self, context_id : int, input_name : str, value : str) :
        self.__libsnark.updatePrimaryInputStr(context_id,s2c(input_name),s2c(value))

    def UpdatePrimaryInputArrayStr(self, context_id : int, input_name : str, array_index : int, value_str : str) :
        self.__libsnark.updatePrimaryInputArrayStr(context_id, s2c(input_name), array_index, s2c(value_str))

    def ReadPK(self, context_id : int) :
        try :
            if exists(ZKLAY_CRS_PK):      
                self.__libsnark.readPK(context_id, s2c(ZKLAY_CRS_PK))
        except Exception as e:
            print(e)

    def ReadVK(self, context_id : int) :
        self.__libsnark.readVK(context_id, s2c(ZKLAY_CRS_VK))

    @print_wrapper(0)
    def proof(self, context_id : int) :
        """
        run proof
        """ 
        try :
            if exists(ZKLAY_CRS_PK):        
                rtn = self.__libsnark.runProof(context_id )
                msg = self.__libsnark.getLastFunctionMsg(context_id).decode('utf-8')
                print ("RunProof : %d , %s" % (rtn , msg) )
        except Exception as e:
            print(e)

    @print_wrapper(0)
    def verify(self, context_id : int) :
        """
        run verify
        """
        rtn = self.__libsnark.runVerify(context_id )
        msg = self.__libsnark.getLastFunctionMsg(context_id).decode('utf-8')
        print ("RunVerify : %d , %s" % (rtn , msg) )

    def finalize(self, context_id : int) :
        """
        Finalize :: it means "memory free"
        """
        rtn = self.__libsnark.finalizeCircuit(context_id )
        msg = self.__libsnark.getLastFunctionMsg(context_id).decode('utf-8')
        print ("FinalizeCircuit : %d , %s" % (rtn , msg) )

    def get_context_id(self, name : str) -> int :
        c_id = self.__libsnark.createCircuitContext(s2c(name) ,PROOF_SYSTEM_GG, 1, None, None, None )
        self.__libsnark.serializeFormat(c_id,ZKLAY_SERIAL)
        return c_id

    def GetVerificationKey(self, context_id : int) -> str :
        return self.__libsnark.serializeVerifyKey(context_id).decode('utf-8')

    def GetProof(self, context_id : int) -> str :
        return self.__libsnark.serializeProof(context_id).decode('utf-8')


class VerificationKey :
    def __init__(
            self,
            alpha : G1Point,
            beta : G2Point,
            delta : G2Point,
            abc : List[G1Point]):
        self.alpha = alpha
        self.beta = beta
        self.delta = delta
        self.abc = abc

    @staticmethod
    def from_json(vk_json: str, flag: bool = True) -> VerificationKey:
        abc = vk_json["ABC"]
        alpha = vk_json["alpha"]
        beta = vk_json["beta"]
        delta = vk_json["delta"]

        def _swap(e  :List[Any]):
            return list(reversed(e))

        if flag:
            beta = [_swap(beta[0]),_swap(beta[1])]
            delta = [_swap(delta[0]),_swap(delta[1])]
    
        abc = [G1Point.from_json_list(element) for element in abc]
        alpha = G1Point.from_json_list(alpha)
        beta = G2Point.from_json_list(beta)
        delta = G2Point.from_json_list(delta)

        return VerificationKey(
            alpha=alpha,
            beta = beta,
            delta=delta,
            abc = abc
        )

    @staticmethod
    def from_list(vk_data : str, flag:bool = True) -> VerificationKey :
        vk_json = json.loads(vk_data)

        return VerificationKey.from_json(vk_json, flag)
    
    @staticmethod
    def from_json_file(file_path: str, flag: bool = True) ->VerificationKey:
        with open(file_path,'r') as f:
            vk_json = json.load(f)
        return VerificationKey.from_json(vk_json, flag)
    

    def to_json_dict(self) -> Dict[str,Any] :
        return {
            "alpha" : self.alpha.to_json_list(),
            "beta" : self.beta.to_json_list(),
            "delta" : self.delta.to_json_list(),
            "ABC" : [abc.to_json_list() for abc in self.abc],
        }


    def to_json(self) -> str :
        return json.dumps(self.to_json_dict(),sort_keys=True,indent=4, separators = (',', ': '))  
        

    @staticmethod
    def verification_key_to_contract_parameters(
            vk: VerificationKey) -> List[int]:
        assert isinstance(vk, VerificationKey)
        return \
            g1_point_to_contract_parameters(vk.alpha) + \
            g2_point_to_contract_parameters(vk.beta) + \
            g2_point_to_contract_parameters(vk.delta) + \
            sum(
                [g1_point_to_contract_parameters(abc)
                 for abc in vk.abc],
                [])


class Proof :
    def __init__(
        self,
        a = G1Point,
        b = G2Point,
        c = G1Point) -> None:
        self.a = a
        self.b = b
        self.c = c

    @staticmethod
    def from_json(proof_json: str) -> Proof:
        A = G1Point(proof_json["a"][0],proof_json["a"][1])
        B = G2Point(proof_json["b"][0],proof_json["b"][1])
        C = G1Point(proof_json["c"][0],proof_json["c"][1])

        def _swap_g2(p: G2Point):
            def _swap(e  :List[Any]):
                return list(reversed(e))
            return G2Point(_swap(p.x_coord), _swap(p.y_coord))
            
        swap_proof_b = _swap_g2(B)


        return Proof(a = A, b = swap_proof_b, c = C)


    @staticmethod
    def proof_from_str(proof_data : str) -> Proof:
        proof_json = json.loads(proof_data)

        return Proof.from_json(proof_json)
        
    @staticmethod
    def from_json_file(file_path: str) -> Proof:
        with open(file_path,'r') as f:
            proof_json = json.load(f)
        return Proof.from_json(proof_json)


    def _proof_to_json_dict(self) -> Dict[str, Any] :

        return {
            "a" : self.a.to_json_list(),
            "b" : self.b.to_json_list(),
            "c" : self.c.to_json_list()
        }

    def to_json(self) :
        return json.dumps(self._proof_to_json_dict()) 
    
    def to_json_show(self) :
        return json.dumps(self._proof_to_json_dict(),sort_keys=True,indent=4, separators = (',', ': ')) 

    @staticmethod
    def from_json_2(proof_json: str) -> Proof:
        return Proof._from_json_dict(json.loads(proof_json))

    @staticmethod
    def _from_json_dict(proof_dict: Dict[str, Any]) -> Proof:
        return Proof(
            a = G1Point.from_json_list(proof_dict["a"]),
            b = G2Point.from_json_list(proof_dict["b"]),
            c = G1Point.from_json_list(proof_dict["c"])
        )

    
    @staticmethod
    def proof_to_contract_parameters(
        proof: Proof) -> List[int]:
        assert isinstance(proof, Proof)

        return \
            g1_point_to_contract_parameters(proof.a) + \
            g2_point_to_contract_parameters(proof.b) + \
            g1_point_to_contract_parameters(proof.c)     


class ExtendedProof:
    """
    A GenericProof and associated inputs
    """
    def __init__(self, proof: Proof, inputs: List[str]):
        self.proof = proof
        self.inputs = inputs

    def to_json_dict(self) -> Dict[str, Any]:
        return {
            "proof": self.proof.to_json(),
            "inputs": self.inputs,
        }

    @staticmethod
    def from_json_dict(
            proof_str : str,
            json_dict: Dict[str, Any]) -> ExtendedProof:
        return ExtendedProof(
            proof=Proof.proof_from_str(proof_str),
            inputs=json_dict["inputs"])


class IStatement(ABC) :
    """
    Abstract base class of statement
    """
    @abstractmethod
    def update_statement(self) -> None :
        pass

    @abstractmethod
    def _to_json_dict(self) -> Dict[str, Any] :
        pass

    @abstractmethod
    def to_json(self) -> None :
        pass


class IWitness(ABC) :
    """
    Abstract base class of witness
    """
    @abstractmethod
    def update_witness(self) -> None :
        pass

    @abstractmethod
    def _to_json_dict(self) -> Dict[str, Any] :
        pass

    @abstractmethod
    def to_json(self) -> str :
        pass


class zklay_statement(IStatement) :
    def __init__(self,
        context_id : int,
        SNARK : snark,
        auditor : ZklayAuditAddressPub,
        rt : int,
        sn : int,
        pk_sen : ZklayAddressPub,
        cm_new : int,
        s_ct_old : S_CT,
        s_ct_new : S_CT,
        v_in : EtherValue,
        v_out : EtherValue,
        p_ct_new : P_CT) -> None:
        self.SNARK = SNARK
        self.context_id = context_id
        self.str_input_name_list = ["G_r","K_u","K_a","addr","k_b","k_u","apk","rt","sn","cm_","pv","pv_"]
        _p_ct_list = p_ct_new.to_param_list()

        self.str_value_list = int_list_to_hex_list([
            _p_ct_list[0],
            _p_ct_list[1],
            _p_ct_list[2],
            pk_sen.addr,
            pk_sen.pk_own,
            pk_sen.pk_enc,
            auditor.apk,
            rt,
            sn,
            cm_new,
            int(v_in.ether()),
            int(v_out.ether())
        ])
       
        self.arr_input_name_list = ["cin","cout","CT"]
        self.arr_value_list = [
            s_ct_old.to_list_hex(),
            s_ct_new.to_list_hex(),
            int_list_to_hex_list([
                _p_ct_list[3],
                _p_ct_list[4],
                _p_ct_list[5]
            ])
        ]
    
    def update_statement(self) :
        for input_name, value in zip(self.str_input_name_list, self.str_value_list) :
            self.SNARK.UpdatePrimaryInput(
                context_id= self.context_id,
                input_name= input_name,
                value = value
            )
        
        for input_name, values in zip(self.arr_input_name_list, self.arr_value_list) :
            for idx, value in enumerate(values) :
                self.SNARK.UpdatePrimaryInputArrayStr(
                    context_id=self.context_id,
                    input_name = input_name,
                    array_index= idx,
                    value_str= value
                )
    

    def to_json(self) -> str :
        return json.dumps(self._to_json_dict(),sort_keys=True,indent=4, separators = (',', ': '))


    def _to_json_dict(self) -> Dict[str, Any] :
        statment_dict = {}
        for input_name, value in zip(self.str_input_name_list, self.str_value_list) :
            statment_dict[input_name] = value
        
        for input_name, values in zip(self.arr_input_name_list, self.arr_value_list) :
            tmp_dict = {}
            for idx, value in enumerate(values) :
                self.SNARK.UpdatePrimaryInputArrayStr(
                    context_id=self.context_id,
                    input_name = input_name,
                    array_index= idx,
                    value_str= value
                )
                tmp_dict[str(idx)] = value
            statment_dict[input_name] = tmp_dict
    
        return statment_dict

    
class zklay_witness(IWitness) :
    def __init__(self,
        context_id : int,
        SNARK : snark,
        sk_sen : ZklayAddressPriv,
        cm_old : int,
        du_old : int,
        v_rev : EtherValue,
        pk_rev : ZklayAddressPub,
        du_new : int,
        v_priv : EtherValue,
        r_new : int,
        k : int,
        path : List[int],
        idx : int) -> None:
        self.context_id = context_id
        self.SNARK = SNARK
        self.str_input_name_list = ["addr_r","k_b_", "k_u_" ,"sk","cm","du","dv","du_","dv_","r","k","direction"]
        self.str_value_list = int_list_to_hex_list([
            pk_rev.addr, 
            pk_rev.pk_own,
            pk_rev.pk_enc,
            sk_sen.usk,
            cm_old,
            du_old,
            int(v_rev.ether()),
            du_new,
            int(v_priv.ether()),
            r_new,
            k,
            idx
        ])
        self.arr_input_name_list = ["intermediateHashes"]
        self.arr_value_list = [
            int_list_to_hex_list(path)
        ]
    

    def update_witness(self) :
        for input_name, value in zip(self.str_input_name_list, self.str_value_list) :
            self.SNARK.UpdatePrimaryInput(
                context_id= self.context_id,
                input_name= input_name,
                value = value
            )
        
        for input_name, values in zip(self.arr_input_name_list, self.arr_value_list) :
            for idx, value in enumerate(values) :
                self.SNARK.UpdatePrimaryInputArrayStr(
                    context_id=self.context_id,
                    input_name = input_name,
                    array_index= idx,
                    value_str= value
                )

    
    def to_json(self) -> str :
        return json.dumps(self._to_json_dict(),sort_keys=True,indent=4, separators = (',', ': '))


    def _to_json_dict(self) -> Dict[str, Any] :
        statment_dict = {}
        for input_name, value in zip(self.str_input_name_list, self.str_value_list) :
            statment_dict[input_name] = value
        
        for input_name, values in zip(self.arr_input_name_list, self.arr_value_list) :
            tmp_dict = {}
            for idx, value in enumerate(values) :
                self.SNARK.UpdatePrimaryInputArrayStr(
                    context_id=self.context_id,
                    input_name = input_name,
                    array_index= idx,
                    value_str= value
                )
                tmp_dict[str(idx)] = value
            statment_dict[input_name] = tmp_dict
    
        return statment_dict


def instance_and_witness(stmt: zklay_statement,
    w: zklay_witness) -> str :
    merged = {**stmt._to_json_dict(), **w._to_json_dict()}

    return json.dumps(merged,sort_keys=True,indent=4, separators = (',', ': '))