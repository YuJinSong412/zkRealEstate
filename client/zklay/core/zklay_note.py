from __future__ import annotations
from zklay.core.constants import VALUE_LENGTH_BYTES, RHO_LENGTH_BYTES, ADDR_LENGTH_BYTES, \
    ZKLAY_NOTE_LENGTH_BYTES
from typing import Dict, Any
import json


_DU_OFFSET_BYTES = 0
_DV_OFFSET_BYTES = _DU_OFFSET_BYTES + VALUE_LENGTH_BYTES
_ADDR_OFFSET_BYTES = _DV_OFFSET_BYTES + RHO_LENGTH_BYTES
assert _ADDR_OFFSET_BYTES + ADDR_LENGTH_BYTES \
    == ZKLAY_NOTE_LENGTH_BYTES


class ZklayNote:
    def __init__(
            self,
            du: str,
            dv: str,
            addr: str) -> None:
        self.du = du
        self.dv = dv
        self.addr = addr

    def _to_json_dict(self):
        return {
            "du": self.du,
            "dv": self.dv,
            "addr": self.addr
        }

    def to_json(self):
        return json.dumps(self._to_json_dict())

    @staticmethod
    def from_json(data_json: str) -> ZklayNote:
        return ZklayNote.from_json_dict(json.loads(data_json))

    @staticmethod
    def from_json_dict(data_dict: Dict[str, Any]) -> ZklayNote:
        return ZklayNote(
            du=data_dict["du"],
            dv=data_dict["dv"],
            addr=data_dict["addr"]
        )

    @staticmethod
    def zklay_note_from_bytes(note_bytes: bytes) -> ZklayNote:
        if len(note_bytes) != ZKLAY_NOTE_LENGTH_BYTES:
            raise ValueError(
                f"note_bytes len {len(note_bytes)}, "
                f"(expected {ZKLAY_NOTE_LENGTH_BYTES})")

        du = note_bytes[_DU_OFFSET_BYTES:_DU_OFFSET_BYTES + VALUE_LENGTH_BYTES]
        dv = note_bytes[_DV_OFFSET_BYTES: _DV_OFFSET_BYTES + RHO_LENGTH_BYTES]
        addr = note_bytes[_ADDR_OFFSET_BYTES: _ADDR_OFFSET_BYTES +
                          ADDR_LENGTH_BYTES]

        return ZklayNote(du=du.hex(), dv=dv.hex(), addr=addr.hex())
