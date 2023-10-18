from Library.zklay_audit_address import ZklayAuditAddress
from Library.zklay_address import ZklayAddress
from Library.context import ClientConfig
import Library.cli_constants as cli_constants
import Library.constants as core_constants
from encryption import SymmetricKeyEncryptionSystem

client_ctx = ClientConfig(
                env = cli_constants.ETH_NETWORK_DEFAULT,
                instance_file = cli_constants.INSTANCE_FILE_DEFAULT,
                token_instance_file = cli_constants.TOKEN_INSTANCE_FILE_DEFAULT,
                address_file = cli_constants.ZKLAY_SECRET_ADDRESS_FILE_DEFAULT,
                audit_address_file =cli_constants.ZKLAY_AUDIT_SECRET_ADDRESS_FILE_DEFAULT,
                wallet_dir = cli_constants.WALLET_DIR_DEFAULT,
                depth = core_constants.DEPTH_TYPE[2],
                hash = cli_constants.HASH_TYPE[1],
                zksnark = core_constants.GROTH16_ZKSNARK,
                ec = core_constants.ELLIPTIC_CURVE_TYPE[0]
            )

auditor = ZklayAuditAddress.generate_keypair(client_ctx)
user = ZklayAddress.generate_keypair(client_ctx)

senc = SymmetricKeyEncryptionSystem(client_ctx, user.usk.usk)
plaintext = int("2af03b0046e15e8f24cdf4515d07cdbc5546ccd73fef162d453c55c6a635f6ee", 16)

ciphertext = senc.encrypt(plaintext)

dec_msg = senc.decrypt(ciphertext)

print(ciphertext)