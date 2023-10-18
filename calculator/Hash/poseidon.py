from __future__ import annotations
from Library.utils import bytes_to_int256, int256_to_bytes
from Library.poseidon_constants import C, S, M, P
from abc import abstractmethod


def _hex_list_to_int_list(l: list[str]) -> list[int]:
    for idx in range(0, len(l)):
        if isinstance(l[idx], list):
            l[idx] = _hex_list_to_int_list(l[idx])
        else:
            l[idx] = int(l[idx], 16)

    return l


class PoseidonBase():
    def __init__(
            self,
            prime: int) -> None:
        self.prime = prime

    @abstractmethod
    def hash(self, *input: bytes) -> bytes:
        pass


class Poseidon(PoseidonBase):
    _C = _hex_list_to_int_list(C)
    _S = _hex_list_to_int_list(S)
    _M = _hex_list_to_int_list(M)
    _P = _hex_list_to_int_list(P)

    def __init__(self, field_prime) -> None:
        # super().__init__(FIELD_PRIME)
        super().__init__(field_prime)
        self.NROUNDSF = 8
        self.NROUNDSP = [56, 57, 56, 60, 60, 63,
                         64, 63, 60, 66, 60, 65, 70, 60, 64, 68]

    def exp5(self, x: int) -> int:
        return pow(x, 5, self.prime)

    def exp5state(self, state: list[int]) -> list[int]:
        return [self.exp5(x) for x in state]

    def Ark(self, state: list[int], c: list[int], it: int) -> list[int]:
        for idx in range(0, len(state)):
            state[idx] = (state[idx] + c[int(it + idx)]) % self.prime

        return state

    def mix(self, state: list[int], t: int, m: list[list]) -> list[int]:
        newState = [0 for _ in range(0, t)]
        for i in range(0, len(state)):
            newState[i] = 0
            for j in range(0, len(state)):
                newState[i] = (newState[i] + (m[j][i] * state[j]) %
                               self.prime) % self.prime

        return newState

    def hash(self, *input: bytes) -> bytes:
        inpBI = list(input)
        inpBI = [bytes_to_int256(e) if isinstance(
            e, bytes) else e for e in inpBI]
        t = len(inpBI) + 1
        if len(inpBI) == 0 or len(inpBI) > len(self.NROUNDSP):
            print(f"invalid inputs length {len(inpBI), len(self.NROUNDSP)}")

        nRoundsF = int(self.NROUNDSF)
        nRoundsP = self.NROUNDSP[t - 2]
        c = C[t - 2]
        s = S[t - 2]
        m = M[t - 2]
        p = P[t - 2]

        state = [0] + inpBI
        state = self.Ark(state, c, 0)

        for idx in range(0, int(nRoundsF / 2 - 1)):
            state = self.exp5state(state)
            state = self.Ark(state, c, (idx + 1) * t)
            state = self.mix(state, t, m)

        state = self.exp5state(state)
        state = self.Ark(state, c, int((nRoundsF / 2) * t))
        state = self.mix(state, t, p)

        for idx in range(0, nRoundsP):
            state[0] = self.exp5(state[0])
            state[0] = (
                state[0] + c[int((nRoundsF / 2 + 1) * t + idx)]) % self.prime

            mul = 0
            newState0 = 0

            for j in range(0, len(state)):
                mul = (s[(t * 2 - 1) * idx + j] * state[j]) % self.prime
                newState0 = (newState0 + mul) % self.prime

            for k in range(1, t):
                mul = 0
                mul = (state[0] * s[(t * 2 - 1) *
                       idx + t + k - 1]) % self.prime
                state[k] = (state[k] + mul) % self.prime

            state[0] = newState0

        for idx in range(0, int(nRoundsF / 2 - 1)):
            state = self.exp5state(state)
            state = self.Ark(state, c, (nRoundsF / 2 + 1)
                             * t + nRoundsP + idx * t)
            state = self.mix(state, t, m)

        state = self.exp5state(state)
        state = self.mix(state, t, m)

        return int256_to_bytes(state[0])
