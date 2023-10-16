
from unittest import TestCase
from zklay.core.mimc import MiMC7, MiMC31
from zklay.core.sha import Sha256
from zklay.core.poseidon import Poseidon


class testHash(TestCase):
    def __init__(self) -> None:
        super().__init__()
        self.bn256_field_prime = 21888242871839275222246405745257275088548364400416034343698204186575808495617
        self.bls12381_field_prime = 52435875175126190479447740508185965837690552500527637822603658699938581184513


    def test_hash_sha256_assert(self):
        
        sha256 = Sha256()

        res = sha256.hash(1,1)
        expected = "c3c3a46684c07d12a9c238787df3049a6f258e7af203e5ddb66a8bd66637e108" # 
        assert expected == res.hex(), f"{res.hex()}, {expected}"

        res = sha256.hash(1,2)
        expected = "d6ba9329f8932c12192b37849f772104d20048f76434a3290512d9d814e4116f" # 
        assert expected == res.hex(), f"{res.hex()}, {expected}"

        res = sha256.hash(
            int("2af03b0046e15e8f24cdf4515d07cdbc5546ccd73fef162d453c55c6a635f6ee",16),
            int("0x2825a2f1be85b53051e3affe3f3d3f68ebc52e7c3adc18d6e869630b67fabf3d",16)
        )
        expected = "8cfe99f9081d64cfb7760e78c3191967149d5a9446acd13442e4123504bfb161" # 
        assert expected == res.hex(), f"{res.hex()}, {expected}"

        print("========================================")
        print("==          SHA256 PASSED             ==")
        print("========================================\n")

    def test_hash_mimc7_assert(self):
        
        mimc7 = MiMC7(self.bn256_field_prime)

        res = mimc7.hash(1,1)
        expected = "2f81229fea90cc0b53ce8ea692be6993d9e6f8ea2fb56751b5d8cf4893f686fd" # 
        assert expected == res.hex(), f"{res.hex()}, {expected}"

        res = mimc7.hash(1,2)
        expected = "161f68835e8f035b8254abccbaadbe9ebedd412340631207067829445fd56c4d" # 
        assert expected == res.hex(), f"{res.hex()}, {expected}"

        res = mimc7.hash(
            int("2af03b0046e15e8f24cdf4515d07cdbc5546ccd73fef162d453c55c6a635f6ee",16),
            int("0x2825a2f1be85b53051e3affe3f3d3f68ebc52e7c3adc18d6e869630b67fabf3d",16)
        )
        expected = "155114ee487f5923c56174604de7a3f7e63b3f46562062b9111737427a91de07" # 
        assert expected == res.hex(), f"{res.hex()}, {expected}"

        print("========================================")
        print("==           MiMC7 PASSED             ==")
        print("========================================\n")
    
    def test_hash_mimc31_assert(self):
        
        mimc31 = MiMC31(self.bn256_field_prime)

        res = mimc31.hash(1,1)
        expected = "1ae0b8d37e64fbecf20e4aceb262ef0ef113f7a81808c07568e05684c515b0a8" # 
        assert expected == res.hex(), f"{res.hex()}, {expected}"

        res = mimc31.hash(1,2)
        expected = "01944497ca5ddc3fab67579eec12e23851ebd3b3f606a9d999a8125a84332f1c" # 
        assert expected == res.hex(), f"{res.hex()}, {expected}"

        res = mimc31.hash(
            int("2af03b0046e15e8f24cdf4515d07cdbc5546ccd73fef162d453c55c6a635f6ee",16),
            int("0x2825a2f1be85b53051e3affe3f3d3f68ebc52e7c3adc18d6e869630b67fabf3d",16)
        )
        expected = "0f3644363c41e14a2820a631397fa000d5afca5c7bd435f39b2242094bf871a1" # 
        assert expected == res.hex(), f"{res.hex()}, {expected}"

        print("========================================")
        print("==          MiMC31 PASSED             ==")
        print("========================================\n")
    
    def test_hash_poseidon_assert(self):
        
        poseidon = Poseidon(self.bn256_field_prime)

        res = poseidon.hash(1,1)
        expected = "007af346e2d304279e79e0a9f3023f771294a78acb70e73f90afe27cad401e81" # 
        assert expected == res.hex(), f"{res.hex()}, {expected}"

        res = poseidon.hash(1,2)
        expected = "115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a" # 
        assert expected == res.hex(), f"{res.hex()}, {expected}"

        res = poseidon.hash(
            int("2af03b0046e15e8f24cdf4515d07cdbc5546ccd73fef162d453c55c6a635f6ee",16),
            int("0x2825a2f1be85b53051e3affe3f3d3f68ebc52e7c3adc18d6e869630b67fabf3d",16)
        )
        expected = "2a8076f26736efc1612a22ed625e49eb853af0aa395113acd9b75cee8274f8ae" # 
        assert expected == res.hex(), f"{res.hex()}, {expected}"

        print("========================================")
        print("==        POSEIDON PASSED             ==")
        print("========================================\n")
        

if __name__ == "__main__" :
    testHash().test_hash_mimc7_assert()
    testHash().test_hash_mimc31_assert()
    testHash().test_hash_sha256_assert()
    testHash().test_hash_poseidon_assert()
