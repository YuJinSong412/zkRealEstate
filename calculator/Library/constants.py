"""
Constants used by zklay.  By convention lengths are given in bits as
`*_LENGTH` and the corresponding `*_LENGTH_BYTES` variable holds the size in
bytes (where this is meaningful).
"""

from typing import List
import os

def bit_length_to_byte_length(bit_length: int) -> int:
    """
    Convert bit length to byte length
    """
    assert \
        bit_length >= 0 and bit_length % 8 == 0, \
        "Not valid bit_length inserted"
    return int(bit_length/8)


# FIELD_PRIME = 52435875175126190479447740508185965837690552500527637822603658699938581184513
FIELD_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617
LOG2_FIELD_PRIME = FIELD_PRIME.bit_length()

CURVE_ORDER = 21888242871839275222246405745257275088696311157297823662689037894645226208583
SUBGROUP_ORDER = 2736030358979909402780800718157159386074658810754251464600343418943805806723
DEFAULT_N = 76484084321990125050991282616845393993780998170065340068946836411360619476297

# GROTH16 constants
GROTH16_ZKSNARK: str = "GROTH16"
GROTH16_MIXER_CONTRACT: str = "Groth16Mixer"

# PGHR13 constants
PGHR13_ZKSNARK: str = "PGHR13"
PGHR13_MIXER_CONTRACT: str = "Pghr13Mixer"

# zkSNARK constants
ZK_SNARK_TYPE: list = [
    GROTH16_ZKSNARK,
]

# CRS constatns
ZKLAY_CRS_PK: str = "ZKlay_CRS_pk.dat"
ZKLAY_CRS_VK: str = "ZKlay_CRS_vk.dat"

# Curve constants
ELLIPTIC_CURVE_BN256 = "BN256"
ELLIPTIC_CURVE_BLS12_381 = "BLS12-381"
ELLIPTIC_CURVE_TYPE: list = [
    ELLIPTIC_CURVE_BLS12_381,
    ELLIPTIC_CURVE_BN256
]

# Depth constants
DEPTH_TYPE: list = [
    "8", "16", "32"
]

# Set of valid snarks
VALID_ZKSNARKS: List[str] = [GROTH16_ZKSNARK, PGHR13_ZKSNARK]

# Merkle tree depth
# ZKLAY_MERKLE_TREE_DEPTH: int = 32
ZKLAY_MERKLE_TREE_DEPTH: int = 8

DEFAULT_NEXT_BLOCK = 1  # ganache
BESU_BLOCK = 5000000
KLAYTN_BLOCK = 76673365

# Nb of input notes
JS_INPUTS: int = 2

# Nb of output notes
JS_OUTPUTS: int = 2

# Gas cost estimates
DEFAULT_GAS: int = 400000

DEPLOYMENT_GAS_WEI: int = ZKLAY_MERKLE_TREE_DEPTH * 25000000

DEFAULT_MIX_GAS_WEI: int = DEPLOYMENT_GAS_WEI

REGISTER_GAS_WEI: int = 250000

REGISTER_MIX_GAS_WEI: int = REGISTER_GAS_WEI

ZKLAY_TRANSFER_GAS_WEI: int = 4000000

# Hash digest length (for commitment and PRFs)
DIGEST_LENGTH: int = 256

VALUE_LENGTH: int = 256
VALUE_LENGTH_BYTES: int = bit_length_to_byte_length(VALUE_LENGTH)

# Public value length (v_pub_in and v_pub_out)
PUBLIC_VALUE_LENGTH: int = 64
PUBLIC_VALUE_LENGTH_BYTES: int = bit_length_to_byte_length(PUBLIC_VALUE_LENGTH)
PUBLIC_VALUE_MASK: int = (1 << PUBLIC_VALUE_LENGTH) - 1

PHI_LENGTH: int = 256
PHI_LENGTH_BYTES: int = bit_length_to_byte_length(PHI_LENGTH)

APK_LENGTH: int = 256
APK_LENGTH_BYTES: int = bit_length_to_byte_length(APK_LENGTH)

RHO_LENGTH: int = 256
RHO_LENGTH_BYTES: int = bit_length_to_byte_length(RHO_LENGTH)

TRAPR_LENGTH: int = 256
TRAPR_LENGTH_BYTES: int = bit_length_to_byte_length(TRAPR_LENGTH)

ADDR_LENGTH: int = 256
ADDR_LENGTH_BYTES: int = bit_length_to_byte_length(ADDR_LENGTH)


NOTE_LENGTH: int = APK_LENGTH + PUBLIC_VALUE_LENGTH + RHO_LENGTH + TRAPR_LENGTH

ZKLAY_NOTE_LENGTH: int = VALUE_LENGTH + RHO_LENGTH + ADDR_LENGTH

NOTE_LENGTH_BYTES: int = bit_length_to_byte_length(NOTE_LENGTH)

ZKLAY_NOTE_LENGTH_BYTES: int = bit_length_to_byte_length(ZKLAY_NOTE_LENGTH)

ZKLAY_CT_LENGTH: int = 256
ZKLAY_CT_LENGTH_BYTES: int = bit_length_to_byte_length(ZKLAY_CT_LENGTH)

# Public inputs are (see BaseMixer.sol):
#   [0                 ] - 1     x merkle root
#   [1                 ] - jsOut x commitment
#   [1 + jsOut         ] - jsIn  x nullifier (partial)
#   [1 + jsOut + jsIn  ] - 1     x hsig (partial)
#   [2 + jsOut + jsIn  ] - JsIn  x message auth tags (partial)
#   [2 + jsOut + 2*jsIn] - 1     x residual bits, v_in, v_out

# Index (in public inputs) of residual bits
RESIDUAL_BITS_INDEX: int = (2 * JS_INPUTS) + JS_OUTPUTS + 2

# Number of full-length digests to be encoded in public inputs
NUM_INPUT_DIGESTS: int = (2 * JS_INPUTS) + 1

# Solidity compiler version
SOL_COMPILER_VERSION: str = 'v0.8.2'

# Seed for MIMC
MIMC_MT_SEED: str = "mimc7_seed"

FILE_PATH = os.path.realpath(__file__)
ZKLAY_CORE_DIR_PATH = os.path.dirname(FILE_PATH)
CLIENT_PATH = os.path.abspath(os.path.join(
    ZKLAY_CORE_DIR_PATH, os.pardir, os.pardir))

CIRCUIT = "ZKlay"

# Units for vpub_in and vpub_out, given in Wei. i.e.
ZKLAY_PUBLIC_UNIT_VALUE: int = 1000000000000000000  # 1 Szabo (10^18 Wei).
