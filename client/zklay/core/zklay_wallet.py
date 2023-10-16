#!/usr/bin/env python3

# Copyright (c) 2021-2021 Zkrypto Inc.
#
# SPDX-License-Identifier: LGPL-3.0+

from __future__ import annotations
from xmlrpc import client
from zklay.core.context import ClientConfig
from zklay.core.zklay_encryption import PublicKeyEncryptionSystem
from zklay.core.zklay_client import TransOutputEvents, receive_note, compute_nullifier, compute_commitment
from zklay.core.constants import DEFAULT_NEXT_BLOCK, BESU_BLOCK, KLAYTN_BLOCK
from zklay.cli.constants import INSTANCE_FILE_DEFAULT
from zklay.core.utils import EtherValue, short_commitment, from_zklay_units, int256_to_bytes
from zklay.cli.debugger import print_msg_box
from zklay.core.zklay_note import ZklayNote
from os.path import join, basename, exists
from os import makedirs
from shutil import move
from typing import Dict, List, Tuple, Optional, Iterator, Any, cast
import glob
import json

# pylint: disable=too-many-instance-attributes

SPENT_SUBDIRECTORY: str = "spent"

# Map nullifier to short commitment string identifying the commitment.
NullifierMap = Dict[str, str]


class ZklayNoteDescription:
    """
    """

    def __init__(self, note: ZklayNote, address: int, commitment: bytes):
        self.note = note
        self.address = address
        self.commitment = int256_to_bytes(commitment) if isinstance(
            commitment, int) else commitment

    def as_input(self) -> Tuple[int, ZklayNote]:
        """
        Returns the description in a form suitable for joinsplit.
        """
        return (self.address, self.note)

    def to_json(self) -> str:
        json_dict = {
            "note": self.note._to_json_dict(),
            "address": str(self.address),
            "commitment": self.commitment.hex(),
        }
        return json.dumps(json_dict, indent=4)

    @staticmethod
    def from_json(json_str: str) -> ZklayNoteDescription:
        json_dict = json.loads(json_str)
        return ZklayNoteDescription(
            note=ZklayNote.from_json_dict(json_dict["note"]),
            address=int(json_dict["address"]),
            commitment=bytes.fromhex(json_dict["commitment"]))


class WalletState:
    """
    State to be saved in the wallet (excluding individual notes). As well as
    the next block to query, we store some information about the state of the
    ZKlay deployment such as the number of notes or the number of distinct
    addresses seen. This can be useful to estimate the security of a given
    transaction.
    """

    def __init__(
            self, next_block: int, num_notes: int, nullifier_map: NullifierMap, amount_ct: int):
        self.next_block = next_block
        self.num_notes = num_notes
        self.nullifier_map = nullifier_map
        self.amount_ct = amount_ct

    def to_json(self) -> str:
        json_dict = {
            "next_block": self.next_block,
            "num_notes": self.num_notes,
            "nullifier_map": self.nullifier_map,
            "amount_ct": self.amount_ct
        }
        return json.dumps(json_dict, indent=4)

    @staticmethod
    def from_json(json_str: str) -> WalletState:
        json_dict = json.loads(json_str)
        return WalletState(
            next_block=int(json_dict["next_block"]),
            num_notes=int(json_dict["num_notes"]),
            nullifier_map=cast(NullifierMap, json_dict["nullifier_map"]),
            amount_ct=json_dict["amount_ct"])


def _load_state_or_default(state_file: str) -> WalletState:
    if not exists(state_file):
        with open(INSTANCE_FILE_DEFAULT, 'r') as f:
            instance_dict = json.loads(f.read())
            if instance_dict["env"] == "besu":
                return WalletState(BESU_BLOCK, 0, {}, 0)
            elif instance_dict["env"] == "klaytn":
                return WalletState(KLAYTN_BLOCK, 0, {}, 0)
            elif instance_dict["env"] == "ganache":
                return WalletState(DEFAULT_NEXT_BLOCK, 0, {}, 0)
    with open(state_file, "r") as state_f:
        return WalletState.from_json(state_f.read())


def _save_state(state_file: str, state: WalletState) -> None:
    with open(state_file, "w") as state_f:
        state_f.write(state.to_json())


class ZklayWallet:
    """
    Very simple class to track the list of notes owned by a ZKlay user.
    Note: this class does not store the notes in encrypted form, and encodes
    some information (including value) in the filename. It is a proof of
    concept implementation and NOT intended to be secure against intruders who
    have access to the file system. However, we expect that a secure
    implementation could expose similar interface and functionality.
    """

    def __init__(
            self,
            mixer_instance: Any,
            username: str,
            client_ctx: ClientConfig,
            pub_enc: PublicKeyEncryptionSystem):
        assert "_" not in username
        self.mixer_instance = mixer_instance
        self.username = username
        self.client_ctx = client_ctx
        self.wallet_dir = client_ctx.wallet_dir
        self.pub_enc = pub_enc
        self.state_file = join(self.wallet_dir, f"state_{username}")
        self.state = _load_state_or_default(self.state_file)
        _ensure_dir(join(self.wallet_dir, SPENT_SUBDIRECTORY))
        # num_notes is pointing next commitment's address
        self.next_addr = self.state.num_notes

    def receive_note(
            self,
            comm_addr: int,
            out_ev: TransOutputEvents) -> Optional[ZklayNoteDescription]:
        # Check this output event to see if it belongs to this wallet.

        our_note = receive_note(out_ev, self.pub_enc)

        if our_note is None:
            return None

        (commit, zklaynote) = our_note
        if not _check_zklay_note(self.client_ctx, commit, zklaynote):
            return None

        note_desc = ZklayNoteDescription(zklaynote, comm_addr, commit)
        self._write_note(note_desc)

        # Add the nullifier to the map in the state file
        nullifier = compute_nullifier(
            self.client_ctx, note_desc.commitment, self.pub_enc.private_key)
        self.state.nullifier_map[nullifier.hex()] = \
            short_commitment(commit)
        return note_desc

    def receive_notes(
            self,
            output_events: List[TransOutputEvents]) -> List[ZklayNoteDescription]:
        """
        Decrypt any notes we can, verify them as being valid, and store them in
        the database.
        """
        new_notes = []

        for out_ev in output_events:
            msg = f"wallet.receive_notes: idx:{self.next_addr}, " + \
                f"comm:{int256_to_bytes(out_ev.cm).hex()[:8]}"
            print_msg_box(msg, width=91)

            note_desc = self.receive_note(self.next_addr, out_ev)
            if note_desc is not None:
                new_notes.append(note_desc)

            self.next_addr = self.next_addr + 1
        self.state.num_notes = self.state.num_notes + len(output_events)

        return new_notes

    def mark_nullifier_used(self, nullifier: bytes) -> str:
        """
        Process nullifiers, marking any of our notes that they spend.
        """
        nullifier_hex = nullifier.hex()
        short_commit = self.state.nullifier_map.get(nullifier_hex, None)
        if short_commit:
            self._mark_note_spent(nullifier_hex, short_commit)

        return short_commit

    def get_notes(self) -> List[ZklayNoteDescription]:
        notes = list()
        wildcard = f"note_{self.username}_*"
        candidates = sorted(
            list(glob.glob(join(self.wallet_dir, wildcard))))
        for candidate in candidates:
            with open(candidate, "r") as note_f:
                notes.append(ZklayNoteDescription.from_json(note_f.read()))

        return notes

    def note_summaries(self) -> Iterator[Tuple[int, str, EtherValue]]:
        """
        Returns simple information that can be efficiently read from the notes
        store.
        """
        return self._decode_note_files_in_dir(self.wallet_dir)

    def spent_note_summaries(self) -> Iterator[Tuple[int, str, EtherValue]]:
        """
        Returns simple info from note filenames in the spent directory.
        """
        return self._decode_note_files_in_dir(
            join(self.wallet_dir, SPENT_SUBDIRECTORY))

    def get_next_block(self) -> int:
        return self.state.next_block

    def update_and_save_state(self, next_block: int) -> None:
        self.state.next_block = next_block
        _save_state(self.state_file, self.state)

    def find_note(self, note_id: str, auto: bool = False) -> ZklayNoteDescription:
        note_file = self._find_note_file(note_id, auto)
        if not note_file:
            return None
        with open(note_file, "r") as note_f:
            return ZklayNoteDescription.from_json(note_f.read())

    def _write_note(self, note_desc: ZklayNoteDescription) -> None:
        """
        Write a note to the database (currently just a file-per-note).
        """
        note_filename = join(self.wallet_dir, self._note_basename(note_desc))
        with open(note_filename, "w") as note_f:
            note_f.write(note_desc.to_json())

    def _mark_note_spent(self, nullifier_hex: str, short_commit: str) -> None:
        """
        Mark a note as having been spent.  Find the file, move it to the `spent`
        subdirectory, and remove the entry from the `nullifier_map`.
        """
        note_file = self._find_note_file(short_commit)
        if note_file is None:
            raise Exception(f"expected to find file for commit {short_commit}")
        spent_file = \
            join(self.wallet_dir, SPENT_SUBDIRECTORY, basename(note_file))
        move(note_file, spent_file)
        del self.state.nullifier_map[nullifier_hex]

    def _note_basename(self, note_desc: ZklayNoteDescription) -> str:
        value_eth = from_zklay_units(int(note_desc.note.dv, 16)).ether()
        cm_str = short_commitment(note_desc.commitment)
        return "note_%s_%04d_%s_%s" % (
            self.username, note_desc.address, cm_str, value_eth)

    @staticmethod
    def _decode_basename(filename: str) -> Tuple[int, str, EtherValue]:
        components = filename.split("_")
        addr = int(components[2])
        short_commit = components[3]
        value = EtherValue(components[4], 'ether')
        return (addr, short_commit, value)

    def _decode_note_files_in_dir(
            self, dir_name: str) -> Iterator[Tuple[int, str, EtherValue]]:
        wildcard = join(dir_name, f"note_{self.username}_*")
        filenames = sorted(glob.glob(wildcard))
        for filename in filenames:
            try:
                yield self._decode_basename(basename(filename))
            except ValueError:
                continue

    def _find_note_file(self, key: str = "0", auto=False) -> Optional[str]:
        """
        Given some (fragment of) address or short commit, try to uniquely
        identify a note file.
        """
        if auto == True:
            wildcard = f"note_{self.username}_*"
            candidates = sorted(
                list(glob.glob(join(self.wallet_dir, wildcard))))
            return candidates[0] if len(candidates) >= 1 else None
        else:
            if len(key) < 5:
                try:
                    addr = "%04d" % int(key)
                    wildcard = f"note_{self.username}_{addr}_*"
                except Exception:
                    return None
            else:
                wildcard = f"note_{self.username}_*_{key}_*"

            candidates = list(glob.glob(join(self.wallet_dir, wildcard)))
            return candidates[0] if len(candidates) == 1 else None


def _check_zklay_note(
    client_ctx: ClientConfig,
    commit: bytes,
    zklaynote: ZklayNote,
) -> bool:

    cm = compute_commitment(client_ctx, zklaynote)
    if commit != cm:
        print(
            f"WARN: bad commitment, commit={commit.hex()[:8]}, computed={cm.hex()[:8]}")
        return False
    if int(zklaynote.dv, 16) == 0: # ignore zero note
        print(
            f"WARN: zero note, commit={commit.hex()[:8]}")
        return False
    return True


def _ensure_dir(directory_name: str) -> None:
    if not exists(directory_name):
        makedirs(directory_name)
