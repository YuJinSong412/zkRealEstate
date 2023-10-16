from unittest import TestCase
from zklay.core.context import ClientConfig
import zklay.cli.constants as cli_constants
import zklay.core.constants as core_constants
from zklay.core.zklay_snark import snark, VerificationKey, Proof


class TestAzerothSnark(TestCase) :
    def __init__(self) -> None:
        super().__init__()
        self.client_ctx = ClientConfig(
                env = cli_constants.ETH_NETWORK_DEFAULT,
                instance_file = cli_constants.INSTANCE_FILE_DEFAULT,
                token_instance_file = cli_constants.TOKEN_INSTANCE_FILE_DEFAULT,
                address_file = cli_constants.ZKLAY_SECRET_ADDRESS_FILE_DEFAULT,
                audit_address_file =cli_constants.ZKLAY_AUDIT_SECRET_ADDRESS_FILE_DEFAULT,
                wallet_dir = cli_constants.WALLET_DIR_DEFAULT,
                depth = core_constants.DEPTH_TYPE[2],
                hash = cli_constants.HASH_TYPE[1],
                zksnark = core_constants.GROTH16_ZKSNARK,
                ec = core_constants.ELLIPTIC_CURVE_TYPE[1]
            )

    def test_zklay_snark(self, name : str) :
        Snark = snark(self.client_ctx)
        context_id = Snark.get_context_id(name)
        Snark.Gen(context_id=context_id)

        vk = VerificationKey.from_list(Snark.GetVerificationKey(context_id=context_id))
        print(vk.to_json())
        
        Snark.proof(context_id=context_id)
        proof = Proof.proof_from_str(Snark.GetProof(context_id = context_id))

        Snark.verify(context_id=context_id)    

if __name__=="__main__" :
    name = "ZKlay"
    TestAzerothSnark().test_zklay_snark(name = name)