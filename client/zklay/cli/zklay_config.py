# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
# Copyright (c) 2021-2021 Zkrypto Inc.
# SPDX-License-Identifier: LGPL-3.0+


from zklay.core.constants import DEPTH_TYPE, ELLIPTIC_CURVE_TYPE, ZK_SNARK_TYPE
from zklay.cli.constants import \
    INSTANCE_FILE_DEFAULT, ZKLAY_SECRET_ADDRESS_FILE_DEFAULT, ZKLAY_AUDIT_SECRET_ADDRESS_FILE_DEFAULT, WALLET_DIR_DEFAULT, \
    ETH_NETWORK_DEFAULT, TOKEN_INSTANCE_FILE_DEFAULT, HASH_TYPE
from zklay.core.context import ClientConfig
from zklay.cli.utils import write_client_config
from click import command, pass_context, ClickException, Context, option, Choice
from typing import Optional
from os.path import exists


@command()
@option(
    "--env",
    default=ETH_NETWORK_DEFAULT,
    help="ENDPOINT name ('ganache', 'klaytn')",
    show_default=True)
@option(
    "--instance-file",
    default=INSTANCE_FILE_DEFAULT,
    help=f"Instance file",
    show_default=True)
@option(
    "--token-instance-file",
    default=TOKEN_INSTANCE_FILE_DEFAULT,
    help=f"Instance file",
    show_default=True)
@option(
    "--address-file",
    default=ZKLAY_SECRET_ADDRESS_FILE_DEFAULT,
    help=f"Zklay zecret address file",
    show_default=True)
@option(
    "--audit-address-file",
    default=ZKLAY_AUDIT_SECRET_ADDRESS_FILE_DEFAULT,
    help=f"Zklay auditor zecret address file",
    show_default=True)
@option(
    "--wallet-dir",
    default=WALLET_DIR_DEFAULT,
    help=f"Wallet directory",
    show_default=True)
@option(
    "--depth",
    "--height",
    default='32',
    help="Merkle Tree height",
    show_default=True,
    type=Choice(DEPTH_TYPE)
)
@option(
    "--hash",
    default='MiMC7',
    help="Type of hash",
    show_default=True,
    type=Choice(HASH_TYPE))
@option(
    "--zksnark",
    help="ZKSNARK name",
    default="GROTH16",
    show_default=True,
    type=Choice(ZK_SNARK_TYPE)
)
@option(
    "--ec",
    "--curve",
    help="Elliptic Curve ('BN256', 'BLS12-381')",
    default="BN256",
    show_default=True,
    type=Choice(ELLIPTIC_CURVE_TYPE))
@pass_context
def config(
    ctx: Context,
    env: Optional[str],
    instance_file: str,
    token_instance_file: str,
    address_file: str,
    audit_address_file: str,
    wallet_dir: str,
    depth: str,
    hash: str,
    zksnark: str,
    ec: str) -> None:
    """
    Generate a new zklay configuration file
    """
    client_ctx = ClientConfig(
        env=env,
        instance_file=instance_file,
        token_instance_file=token_instance_file,
        address_file=address_file,
        audit_address_file=audit_address_file,
        wallet_dir=wallet_dir,
        depth=depth,
        hash=hash,
        zksnark=zksnark,
        ec=ec
    )
    write_client_config(client_ctx)
    client_ctx.show()
    
    
