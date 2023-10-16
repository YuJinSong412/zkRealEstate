# Copyright (c) 2021-2021 Zkrypto Inc.
#
# SPDX-License-Identifier: LGPL-3.0+

from zklay.cli.utils import load_eth_address, load_eth_private_key, \
    create_zklayclient_and_zklaydesc, \
    load_token_description_from_ctx
from zklay.core.utils import EtherValue
from test_commands.deploy_test_token import mint_token
from zklay.core.contracts import token_approve
from zklay.cli.debugger import print_wrapper
from click import command, option, pass_context, Context


@command()
@option("--deployer_path", help="Deployer Path (ex: ./[deployer]")
@option("--spender_path", help="Spender Path (ex: ./[spender]")
@option("--value", help="Mint value")
@print_wrapper(num=0)
@pass_context
def mint(
        ctx: Context,
        deployer_path: str,
        spender_path: str,
        value: str) -> None:
    """
    Attempt to retrieve new notes for the key in <key-file>
    """
    client_ctx = ctx.obj

    deployer_eth_address = load_eth_address(path=deployer_path)
    deployer_eth_priv_key = load_eth_private_key(path=deployer_path)
    spender_eth_address = load_eth_address(path=spender_path)
    spender_eth_priv_key = load_eth_private_key(path=spender_path)

    zklay_client, _ = create_zklayclient_and_zklaydesc(
        client_ctx)

    token_ = load_token_description_from_ctx(client_ctx)

    token = zklay_client.web3.eth.contract(
        address=token_.address,
        abi=token_.abi
    )

    mint_token(
        zklay_client.web3,
        token,
        spender_eth_address,
        deployer_eth_address,
        deployer_eth_priv_key,
        EtherValue(value)
    )

    token_approve(
        web3=zklay_client.web3,
        token=token,
        sender=zklay_client.zklay_instance.address,
        receiver=spender_eth_address,
        receiver_eth_priv_key=spender_eth_priv_key
    )
