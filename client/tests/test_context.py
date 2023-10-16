from json import load
from unittest import TestCase
from zklay.core.context import ClientConfig
import zklay.cli.constants as cli_constants
import zklay.core.constants as core_constants
from zklay.cli.utils import load_client_config, write_client_config

class TestContext(TestCase):
    def test_context(self):
        ctx = ClientConfig(
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

        ctx_json = ctx.to_json()
        write_client_config(ctx)
        ctx = load_client_config()

        assert ctx.to_json() == ctx_json

if __name__ == "__main__":
    TestContext().test_context()
