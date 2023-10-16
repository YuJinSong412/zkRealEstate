# Copyright (c) 2021-2021 Zkrypto Inc.

# SPDX-License-Identifier: LGPL-3.0+

from http import client
from zklay.cli.constants import INSTANCE_FILE_DEFAULT, TOKEN_INSTANCE_FILE_DEFAULT
from test_commands.deploy_test_token import deploy_token
from zklay.cli.utils import \
    open_web3_from_ctx, get_erc20_instance_description, load_eth_address, \
    load_eth_private_key, write_mixer_description, MixerDescription, get_token_description, \
    write_token_description
from zklay.cli.debugger import print_wrapper, print_value
from zklay.core.zklay_client import ZklayClient
from click import Context, command, option, pass_context
from typing import Optional


@command()
@option("--eth-addr", help="Sender eth address or address filename")
@option("--eth-private-key", help="Sender's eth private key file")
@option(
    "--instance-out",
    default=INSTANCE_FILE_DEFAULT,
    help=f"File to write deployment address to (default={INSTANCE_FILE_DEFAULT})")
@option(
    "--token-instance-out",
    default=TOKEN_INSTANCE_FILE_DEFAULT,
    help=f"File to write deployment address to (default={TOKEN_INSTANCE_FILE_DEFAULT})")
@option("--deploy-gas", help="Maximum gas, in Wei")
@print_wrapper(num=0)
@pass_context
def deploy(
        ctx: Context,
        eth_addr: Optional[str],
        eth_private_key: Optional[str],
        instance_out: str,
        token_instance_out: str,
        deploy_gas: Optional[str]) -> None:
    """
    Deploy the zklay contracts and record the instantiation details.
    """

    DEPLOY_TOKEN_GAS = 8000000
    eth_address = load_eth_address(eth_addr)
    eth_private_key_data = load_eth_private_key(eth_private_key)
    client_ctx = ctx.obj
    
    web3 = open_web3_from_ctx(client_ctx)

    print_value(eth_address, name="eth_address", func_name="deploy")
    print_value(instance_out, name="instance_out", func_name="deploy")

    token_instance = deploy_token(
        web3, eth_address, eth_private_key_data, DEPLOY_TOKEN_GAS)

    token_instance_desc = get_erc20_instance_description(
        token_instance.address)

    token_desc = get_token_description(token_instance)

    _, zklay_instance_desc = ZklayClient.deploy(
        web3,
        client_ctx,
        "ZKlay",
        eth_address,
        eth_private_key_data,
        token_instance.address,
        int(deploy_gas) if deploy_gas else None)

    zklay_desc = MixerDescription(
        zklay_instance_desc, token_instance_desc, client_ctx.env)
    write_mixer_description(instance_out, zklay_desc)
    write_token_description(token_instance_out, token_desc)
    
