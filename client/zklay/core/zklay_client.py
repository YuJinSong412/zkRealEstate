#!/usr/bin/env python3

# Copyright (c) 2021-2021 Zkrypto Inc
#
# SPDX-License-Identifier: LGPL-3.0+

from __future__ import annotations
from zklay.core.montgomery_curve import CurveParameters
import os
import json
import zklay.cli.utils as cli_utils
import zklay.core.contracts as contracts
import zklay.core.constants as constants
from zklay.core.zklay_encryption import SymmetricKeyEncryptionSystem, PublicKeyEncryptionSystem, P_CT, S_CT
from zklay.core.zklay_snark import snark, VerificationKey, Proof, zklay_statement, zklay_witness, instance_and_witness
from zklay.core.zklay_note import ZklayNote
from zklay.core.utils import EtherValue, to_zklay_units, \
    get_contracts_dir, int256_to_bytes, Pocket, bytes_to_int256, random_field_element
from zklay.cli.debugger import print_wrapper, print_value
from typing import Tuple, Dict, List, Iterator, Optional, Any
from zklay.core.zklay_audit_address import ZklayAuditAddressPub
from zklay.core.zklay_address import ZklayAddressPub, ZklayAddressPriv
from zklay.core.context import ClientConfig
from zklay.core.hash import Hash
from zklay.core.zklay_rollup import RollupParameters


ZERO_UNITS_HEX = "0000000000000000"
ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"


class TransCallDescription:
    def __init__(
            self,
            rt: int,
            sn: int,
            pk: ZklayAddressPub,
            s_ct_new: S_CT,
            v_in: EtherValue,
            v_out: EtherValue,
            TransOutput: TransOutputEvents,
            toEoA: str):
        self.rt = rt
        self.sn = sn
        self.pk = pk
        self.s_ct_new = s_ct_new
        self.v_in = v_in
        self.v_out = v_out
        self.TransOutput = TransOutput
        self.toEoA = toEoA

    def to_json(self) -> str:
        return json.dumps(self._to_json_dict())

    def _to_json_dict(self) -> Dict[str, Any]:
        return {
            "rt": self.rt,
            "sn": self.sn,
            "pk": self.pk._to_json_dict(),
            "s_ct_new": self.s_ct_new._to_json_dict(),
            "v_in": to_zklay_units(self.v_in),
            "v_out": to_zklay_units(self.v_out),
            "TransOutput": self.TransOutput._to_json_dict(),
            "toEoA": self.toEoA
        }

    @staticmethod
    def from_json(trans_call_desc_json: str) -> TransCallDescription:
        return TransCallDescription._from_json_dict(json.loads(trans_call_desc_json))

    @staticmethod
    def _from_json_dict(trans_call_desc_dict: Dict[str, Any]) -> TransCallDescription:
        return TransCallDescription(
            rt=trans_call_desc_dict["rt"],
            sn=trans_call_desc_dict["sn"],
            pk=ZklayAddressPub._from_json_dict(trans_call_desc_dict["pk"]),
            s_ct_new=S_CT._from_json_dict(trans_call_desc_dict["s_ct_new"]),
            v_in=EtherValue(trans_call_desc_dict["v_in"]),
            v_out=EtherValue(trans_call_desc_dict["v_out"]),
            TransOutput=TransOutputEvents._from_json_dict(
                trans_call_desc_dict["TransOutput"]),
            toEoA=trans_call_desc_dict["toEoA"]
        )


class TransParameters:
    def __init__(
            self,
            proof: Proof,
            trans_call_desc: TransCallDescription) -> None:
        self.proof = proof
        self.trans_call_desc = trans_call_desc

    def to_json(self) -> str:
        return json.dumps(self._to_json_dict())

    def _to_json_dict(self) -> Dict[str, Any]:
        return {
            "proof": self.proof._proof_to_json_dict(),
            "trans_call_desc": self.trans_call_desc._to_json_dict()
        }

    def write_trans_param(self, file: str, path: Optional[str] = None) -> None:
        if path != None:
            file = path + "/" + file
        with open(file, "w") as f:
            f.write(self.to_json())

    @staticmethod
    def from_json(trans_param_json: str) -> TransParameters:
        return TransParameters._from_json_dict(json.loads(trans_param_json))

    @staticmethod
    def _from_json_dict(trans_param_dict: Dict[str, Any]) -> TransParameters:
        return TransParameters(
            proof=Proof._from_json_dict(trans_param_dict["proof"]),
            trans_call_desc=TransCallDescription._from_json_dict(
                trans_param_dict["trans_call_desc"])
        )

    @staticmethod
    def load_trans_param(file: str, path: Optional[str] = None) -> TransParameters:
        if path != None:
            file = path + "/" + file
        with open(file, "r") as f:
            return TransParameters.from_json(f.read())


def trans_parameters_to_contract_arguments(
        trans_parameters: TransParameters) -> List[Any]:
    proof_contract_params = Proof.proof_to_contract_parameters(
        trans_parameters.proof)

    trans_output = trans_parameters.trans_call_desc.TransOutput
    v_in = to_zklay_units(trans_parameters.trans_call_desc.v_in)
    v_out = to_zklay_units(trans_parameters.trans_call_desc.v_out)

    return [
        proof_contract_params,
        [
        trans_parameters.trans_call_desc.rt,
        trans_parameters.trans_call_desc.sn,
        *(trans_parameters.trans_call_desc.pk.to_list()),
        trans_output.cm,
        *(trans_parameters.trans_call_desc.s_ct_new.to_param_list()),
        v_in, v_out,
        *(trans_output.p_ct.to_param_list())
        ],
        trans_parameters.trans_call_desc.toEoA
    ]


class TransOutputEvents:
    def __init__(
            self,
            cm: int,
            addr: int,
            p_ct: P_CT):
        self.cm = cm
        self.addr = addr
        self.p_ct = p_ct

    def to_json(self) -> str:
        return json.dumps(self._to_json_dict())

    def _to_json_dict(self) -> Dict[Any, Any]:
        return {
            "cm": self.cm,
            "addr": self.addr,
            "p_ct": self.p_ct._to_json_dict(),
        }

    @staticmethod
    def from_json(trans_output_event_json: str) -> TransOutputEvents:
        return TransOutputEvents._from_json_dict(json.loads(trans_output_event_json))

    @staticmethod
    def _from_json_dict(trans_output_event_dict: Dict[str, Any]) -> TransOutputEvents:
        return TransOutputEvents(
            cm=trans_output_event_dict["cm"],
            addr=trans_output_event_dict["addr"],
            p_ct=P_CT._from_json_dict(trans_output_event_dict["p_ct"])
        )


class TransResult:
    def __init__(
            self,
            new_merkle_root: bytes,
            nullifier: bytes,
            output_events: List[TransOutputEvents]):
        self.new_merkle_root = new_merkle_root
        self.nullifier = nullifier
        self.output_events = output_events


def event_args_to_trans_result(event_args: Any) -> TransResult:
    try:
        p_ct = P_CT(
            event_args.c_0,
            event_args.c_1,
            event_args.c_2,
            [
                event_args.c_3_0,
                event_args.c_3_1,
                event_args.c_3_2
            ]
        )

        out_events = [TransOutputEvents(
            event_args.com,
            event_args.addr,
            p_ct)]
        return TransResult(
            new_merkle_root=event_args.root,
            nullifier=event_args.nullifier,
            output_events=out_events)
    except Exception as e:
        print(f"[ERROR] :: <event_args_to_trans_result> [{e}]")


def get_trans_result(
        web3: Any,
        zklay_instance: Any,
        start_block: int,
        end_block: int,
        batch_size: Optional[int] = None) -> Iterator[TransResult]:

    logs = contracts.get_event_logs(
        web3,
        zklay_instance,
        "LogTrans",
        start_block,
        end_block,
        batch_size
    )

    for event_data in logs:
        yield event_args_to_trans_result(event_data.args)


class ZklayClient:
    """
    Interface to operations on the Mixer contract.
    """

    def __init__(
            self,
            web3: Any,
            zklay_instance: Any,
            client_ctx: ClientConfig):
        self.web3 = web3
        self.zklay_instance = zklay_instance
        self.client_ctx = client_ctx
        self.field_prime = CurveParameters(self.client_ctx).field_prime

    @print_wrapper(num=1)
    def create_trans_args(
            self,
            circuit_name: str,
            zklay_wallet: ZklayWallet,
            auditor_pub: ZklayAuditAddressPub,
            sender_pub: ZklayAddressPub,
            sender_priv: ZklayAddressPriv,
            receiver_pub: ZklayAddressPub,
            pocket: Pocket,
            toEoA: str,
            note_idx: Optional[int] = None) -> Tuple[TransParameters, RollupParameters]:

        addr = int(sender_pub.addr)  # int
        addr_ = int(receiver_pub.addr)  # int
        sk = int(sender_priv.usk)  # int

        hash = Hash(self.client_ctx)
        senc = SymmetricKeyEncryptionSystem(self.client_ctx, sender_priv.usk)
        penc = PublicKeyEncryptionSystem(self.client_ctx, sender_priv.usk)

        if note_idx == None:
            du_old = random_field_element(self.field_prime) #o_{old}
            dv = 0 #v_{in}^{priv}
            cm_old = hash.hash(du_old, dv, addr)  # int
            sn = hash.hash(cm_old, sk)  # int
            idx = zklay_wallet.next_addr
        else: #cm을 사용할 경우
            notes = zklay_wallet.get_notes()
            assert len(notes) > note_idx
            cm_old = bytes_to_int256(notes[note_idx].commitment)
            sn = hash.hash(cm_old, sk)
            idx = notes[note_idx].address
            du_old = int(notes[note_idx].note.du, 16)
            dv = int(notes[note_idx].note.dv, 16)

        ct_old, r_old = self.zklay_instance.functions.getCiphertext(
            int256_to_bytes(addr)).call()

        s_ct_old = S_CT(r_old, ct_old)
        v = 0 if s_ct_old.empty() else senc.decrypt(s_ct=s_ct_old)

        print_value(v, name="Hidden amount", func_name="create_trans_args")

        rt_old = self.zklay_instance.functions.getRootTop().call()  # int

        du_ = random_field_element(self.field_prime)  # int
        receiver_pub.pk_enc

        p_ct_new, r, k = penc.encrypt(
            auditor_pub,
            receiver_pub,
            du_,
            int(pocket.v_priv.ether()),
            addr_,
        )

        v_ = (v + dv -
              int(pocket.v_priv.ether()) + int(pocket.v_in.ether()) - int(pocket.v_out.ether())) % self.field_prime

        s_ct_new = senc.encrypt(v_)

        cm_new = hash.hash(du_, int(pocket.v_priv.ether()), addr_)

        new_trans_output = TransOutputEvents(
            cm=cm_new,
            addr=addr,
            p_ct=p_ct_new)

        trans_call_desc = TransCallDescription(
            rt=rt_old,
            sn=sn,
            pk=sender_pub,
            s_ct_new=s_ct_new,
            v_in=pocket.v_in,
            v_out=pocket.v_out,
            TransOutput=new_trans_output,
            toEoA=toEoA
        )

        Snark = snark(self.client_ctx)
        context_id = Snark.get_context_id(circuit_name)
        Snark.reGen(context_id=context_id)

        stmt = zklay_statement(
            context_id=context_id,
            SNARK=Snark,
            auditor=auditor_pub,
            rt=rt_old,
            sn=sn,
            pk_sen=sender_pub,
            cm_new=cm_new,
            s_ct_old=s_ct_old,
            s_ct_new=s_ct_new,
            v_in=pocket.v_in,
            v_out=pocket.v_out,
            p_ct_new=p_ct_new)

        stmt.update_statement()

        path = self.zklay_instance.functions.getMerklePath(idx).call()

        w = zklay_witness(
            context_id=context_id,
            SNARK=Snark,
            sk_sen=sender_priv,
            cm_old=cm_old,
            du_old=du_old,
            v_rev=EtherValue(dv),
            pk_rev=receiver_pub,
            du_new=du_,
            v_priv=pocket.v_priv,
            r_new=r,
            k=k,
            path=path,
            idx=idx
        )

        w.update_witness()

        print(instance_and_witness(stmt, w))

        Snark.proof(context_id=context_id)
        proof = Proof.proof_from_str(Snark.GetProof(context_id=context_id))
        print(proof.to_json_show())

        rollup_param = RollupParameters(stmt, proof)

        """
            debug: client verify
        """
        Snark.ReadVK(context_id=context_id)
        Snark.verify(context_id=context_id)

        return TransParameters(proof, trans_call_desc), rollup_param

    def _create_registerUser_call(
            self,
            addr: bytes) -> Any:
        return self.zklay_instance.functions.registerUser(addr)

    @print_wrapper(num=1)
    def registerUser(
            self,
            addr: bytes,
            user_eth_address: str,
            user_eth_private_key: Optional[bytes],
            tx_value: EtherValue,
            register_user_gas: Optional[int] = None) -> str:
        """
        Register User contracts
        """
        register_user_gas = register_user_gas or constants.REGISTER_GAS_WEI

        register_user_call = self._create_registerUser_call(addr)

        tx_hash = contracts.send_contract_call(
            self.web3,
            register_user_call,
            user_eth_address,
            user_eth_private_key,
            tx_value,
            register_user_gas
        )
        tx_receipt = self.web3.eth.waitForTransactionReceipt(tx_hash, 10000)
        print(
            f"registerUser:   tx_hash={tx_hash[0:8].hex()}, " +
            f"  gasUsed={tx_receipt.gasUsed}")

        return tx_hash.hex()

    def _create_registerAuditor_call(
            self,
            apk: int) -> Any:
        return self.zklay_instance.functions.registerAuditor(apk)

    @print_wrapper(num=1)
    def registerAuditor(
            self,
            audit_public_key: int,
            auditor_eth_address: str,
            tx_value: EtherValue,
            auditor_eth_private_key: Optional[bytes] = None,
            register_auditor_gas: Optional[str] = None) -> str:
        """
        Register Auditor contracts
        """
        register_auditor_gas = register_auditor_gas or constants.REGISTER_GAS_WEI
        register_Auditor_call = self._create_registerAuditor_call(
            audit_public_key)
        tx_hash = contracts.send_contract_call(
            self.web3,
            register_Auditor_call,
            auditor_eth_address,
            auditor_eth_private_key,
            tx_value,
            register_auditor_gas
        )
        tx_receipt = self.web3.eth.waitForTransactionReceipt(tx_hash, 10000)
        print(
            f"registerAuditor:   tx_hash={tx_hash[0:8].hex()}, " +
            f"  gasUsed={tx_receipt.gasUsed}")
        return tx_hash.hex()

    @staticmethod
    @print_wrapper(num=1)
    def deploy(
            web3: Any,
            client_ctx: ClientConfig,
            circuit_name: str,
            deployer_eth_address: str,
            deployer_eth_private_key: Optional[bytes],
            token_address: Optional[str] = None,
            deploy_gas: Optional[int] = None
    ) -> Tuple[ZklayClient, contracts.InstanceDescription]:
        """
        Deploy ZKlay contracts.
        """

        Snark = snark(client_ctx)
        context_id = Snark.get_context_id(name=circuit_name)
        Snark.Gen(context_id=context_id)

        vk = VerificationKey.from_list(
            Snark.GetVerificationKey(context_id=context_id))
        print(vk.to_json())
        vk_contract_parameter = VerificationKey.verification_key_to_contract_parameters(
            vk)
        deploy_gas = deploy_gas or constants.DEPLOYMENT_GAS_WEI

        contracts_dir = get_contracts_dir()
        contract_name = cli_utils.get_contract_name(client_ctx)
        mixer_src = os.path.join(contracts_dir, contract_name + ".sol")

        # Constructor parameters have the form:
        #   uint256 mk_depth
        #   address token
        #   ... snark-specific key data ...
        constructor_parameters: List[Any] = [
            int(client_ctx.depth),
            token_address or ZERO_ADDRESS,     # token
            vk_contract_parameter,  # vk
            cli_utils.get_hash_num(client_ctx.hash),
        ]
        mixer_description = contracts.InstanceDescription.deploy(
            web3,
            mixer_src,
            contract_name,
            deployer_eth_address,
            deployer_eth_private_key,
            deploy_gas,
            compiler_flags={},
            args=constructor_parameters)
        zklay_instance = mixer_description.instantiate(web3)
        client = ZklayClient(web3, zklay_instance, client_ctx)

        return client, mixer_description

    @print_wrapper(num=1)
    def anontransfer(
            self,
            trans_param: TransParameters, #proof랑 파라미터 받아와서 
            sender_eth_address: str,
            sender_eth_private_key: Optional[bytes],
            tx_value: EtherValue,
            call_gas: int = constants.ZKLAY_TRANSFER_GAS_WEI) -> str:
        anontransfer_call = self._create_anontransfer_call(trans_param)
        tx_hash = contracts.send_contract_call( #컨트랙트 호출 zkTransfer_{SC}
            self.web3,
            anontransfer_call,
            sender_eth_address,
            sender_eth_private_key,
            tx_value,
            call_gas)

        tx_receipt = self.web3.eth.waitForTransactionReceipt(tx_hash, 10000)
        print(
            f"anontransfer:   tx_hash={tx_hash[0:8].hex()}, " +
            f"  gasUsed={tx_receipt.gasUsed}")

         # print error
        if tx_receipt.status == 0:
            try:
                contracts.local_contract_call(
                    anontransfer_call,
                    sender_eth_address,
                    tx_value,
                    call_gas
                )
            except ValueError as e:
                print(e)
                
        return tx_hash.hex()

    def _create_anontransfer_call(
            self,
            trans_parameters: TransParameters) -> Any:

        trans_params_eth = trans_parameters_to_contract_arguments(
            trans_parameters)

        return self.zklay_instance.functions.zkTransfer(*trans_params_eth)


def receive_note(
        out_ev: TransOutputEvents,
        penc: PublicKeyEncryptionSystem) -> Optional[Tuple[bytes, ZklayNote]]:
    """
    Given the receivers secret key, and the event data from a transaction
    (encrypted notes), decrypt any that are intended for the receiver. Return
    tuples `(<address-in-merkle-tree>, ZKlayNote)`. Callers should record the
    address-in-merkle-tree along with ZKlayNote information, for convenience
    when spending the notes.
    """
    try:
        res = penc.decrypt(out_ev.p_ct)
        msg = int256_to_bytes(
            res[0]) + int256_to_bytes(res[1]) + int256_to_bytes(res[2])
        return (
            int256_to_bytes(out_ev.cm),
            ZklayNote.zklay_note_from_bytes(msg))
    except Exception as err:
        print(f"[ERROR] :: {err}")


def compute_commitment(client_ctx: ClientConfig, zklay_note: ZklayNote) -> bytes:
    """
    Used by the recipient of a payment to recompute the commitment and check
    the membership in the tree to confirm the validity of a payment
    """
    hash = Hash(client_ctx)
    cm = int256_to_bytes(hash.hash(
        bytes.fromhex(zklay_note.du),
        bytes.fromhex(zklay_note.dv),
        bytes.fromhex(zklay_note.addr)))

    return cm


def compute_nullifier(
        client_ctx: ClientConfig,
        cm: bytes,
        sk: int) -> bytes:
    hash = Hash(client_ctx)
    sn = int256_to_bytes(hash.hash(cm, sk))
    return sn
