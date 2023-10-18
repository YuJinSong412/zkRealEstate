from Library.constants import MIMC_MT_SEED
from Crypto.Hash import keccak
from abc import abstractmethod

class MiMCBase():

    def __init__(
            self,
            seed_str: str,
            prime: int,
            num_rounds: int):
        self.seed = _keccak_256(_str_to_bytes(seed_str))
        self.prime = prime
        self.num_rounds = num_rounds

    def encrypt(
            self,
            message: int,
            ek: int) -> int:
        result = message % self.prime
        key = ek % self.prime
        round_constant: int = self.seed

        # The round constant in round 0 is 0 (see [AGRRT16])
        result = self.mimc_round(result, key, 0)

        for _ in range(self.num_rounds - 1):
            round_constant = _update_round_constant(round_constant)
            result = self.mimc_round(result, key, round_constant)

        # Add key to the final result (see [AGRRT16])
        return (result + key) % self.prime

    def hash(self, *input: bytes) -> bytes:
        """
        Apply Miyaguchi-Preneel to the output of the encrypt function.
        """
        def bigint_to_bytes(input):
            return input.to_bytes(256, "big")

        def _hash(left: bytes, right: bytes) -> bytes:
            x = left % self.prime if isinstance(left, int) else int.from_bytes(
                left, byteorder='big') % self.prime
            y = right % self.prime if isinstance(right, int) else int.from_bytes(
                right, byteorder='big') % self.prime

            result = (self.encrypt(x, y) + x + y) % self.prime
            return result.to_bytes(32, byteorder='big')

        data_list = list(input)
        length = len(data_list)
        for i, data in enumerate(data_list):
            if isinstance(data, int):
                data_list[i] = bigint_to_bytes(data)

        if length == 1:
            return _hash(data_list[0], data_list[0])
        else:
            res = _hash(data_list[0], data_list[1])
            for i in range(0, len(data_list) - 2):
                res = _hash(res, data_list[i + 2])
            return res

    @abstractmethod
    def mimc_round(self, message: int, key: int, rc: int) -> int:
        pass


class MiMC7(MiMCBase):
    """
    MiMC specialized for Fr in ALT-BN128, in which the exponent is 7 and 91
    rounds are used.
    """

    def __init__(self, field_prime, seed_str: str = MIMC_MT_SEED):
        MiMCBase.__init__(
            self,
            seed_str,
            field_prime,  # noqa
            # pylint: disable=line-too-long
            91)

    def mimc_round(self, message: int, key: int, rc: int) -> int:
        xored = (message + key + rc) % self.prime
        return xored ** 7 % self.prime


class MiMC31(MiMCBase):
    """
    MiMC implementation using exponent of 31 and 51 rounds. Note that this is
    suitable for BLS12-377, since 31=2^5-1, and 1 == gcd(31, r-1). See
    [AGRRT16] for details.
    """

    def __init__(self, field_prime, seed_str: str = MIMC_MT_SEED):
        MiMCBase.__init__(
            self,
            seed_str,
            field_prime,  # noqa
            51)

    def mimc_round(self, message: int, key: int, rc: int) -> int:
        a = (message + key + rc) % self.prime
        a_2 = (a * a) % self.prime
        a_4 = (a_2 * a_2) % self.prime
        a_8 = (a_4 * a_4) % self.prime
        a_16 = (a_8 * a_8) % self.prime
        return (a_16 * a_8 * a_4 * a_2 * a) % self.prime


def _str_to_bytes(value: str) -> bytes:
    return value.encode('ascii')


def _int_to_bytes32(value: int) -> bytes:
    return value.to_bytes(32, 'big')


def _keccak_256(data_bytes: bytes) -> int:
    h = keccak.new(digest_bits=256)
    h.update(data_bytes)
    hashed = h.digest()
    return int.from_bytes(hashed, 'big')


def _update_round_constant(rc: int) -> int:
    return _keccak_256(_int_to_bytes32(rc))
