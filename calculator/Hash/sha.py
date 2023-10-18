from abc import abstractmethod
import hashlib


class ShaBase():
    def __init__(
            self) -> None:
        pass

    @abstractmethod
    def hash(self, *input: bytes) -> bytes:
        pass


class Sha256(ShaBase):
    def __init__(self) -> None:
        super().__init__()

    def hash(self, *input: bytes) -> bytes:
        def _bigint_to_bytes(input):
            return input.to_bytes(32, "big")

        res = None
        data_list = list(input)
        for i, data in enumerate(input):
            if isinstance(data, int):
                data_list[i] = _bigint_to_bytes(data)
            elif isinstance(data, bytes):
                data_list[i] = data
            if i == 0:
                res = data_list[i]
            else:
                res += data_list[i]
        hashed = int(hashlib.sha256(res).hexdigest(), 16)

        return hashed.to_bytes(32, byteorder='big')
