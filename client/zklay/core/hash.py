from abc import abstractmethod
from zklay.core.utils import bytes_to_int256
from zklay.core.sha import Sha256
from zklay.core.mimc import MiMC7
from zklay.core.poseidon import Poseidon
from zklay.core.context import ClientConfig
from zklay.core.constants import FIELD_PRIME
from zklay.core.montgomery_curve import CurveParameters


class Hash():
    def __init__(
            self,
            client_ctx: ClientConfig) -> None:
        self.client_ctx = client_ctx
        self.field_prime = CurveParameters(client_ctx).field_prime
        self.hash_base = self.__get_hash_base()

    def __get_hash_base(self):
        if self.client_ctx.hash == "MiMC7":
            return MiMC7(self.field_prime)
        elif self.client_ctx.hash == "SHA256":
            return Sha256()
        elif self.client_ctx.hash == "Poseidon":
            return Poseidon(self.field_prime)

    def hash(self, *input: bytes) -> int:
        assert self.hash_base

        output_bytes = self.hash_base.hash(*input)

        return bytes_to_int256(output_bytes) % self.field_prime
