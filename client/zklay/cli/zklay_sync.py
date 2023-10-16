# Copyright (c) 2021-2021 Zkrypto Inc.
#
# SPDX-License-Identifier: LGPL-3.0+

from zklay.cli.utils import load_zklay_address_secret, open_zklay_wallet, load_zklay_audit_address_secret, \
    create_zklayclient_and_zklaydesc, do_sync_trans, load_zklay_address_public
from zklay.cli.debugger import print_wrapper
from click import command, option, pass_context, Context
from typing import Optional


@command()
@option("--wait-tx", help="Wait for tx hash")
@option("--batch-size", type=int, help="Override blocks per query")
@print_wrapper(num=0)
@pass_context
def sync(ctx: Context, wait_tx: Optional[str], batch_size: Optional[int]) -> None:
    """
    Attempt to retrieve new notes for the key in <key-file>
    """
    client_ctx = ctx.obj

    zklay_client, _ = create_zklayclient_and_zklaydesc(
        client_ctx)

    try:
        js_secret = load_zklay_address_secret(client_ctx)
    except FileNotFoundError:
        js_secret = load_zklay_audit_address_secret(client_ctx)

    pub = load_zklay_address_public(client_ctx)

    zklay_wallet = open_zklay_wallet(
        zklay_instance=zklay_client.zklay_instance,
        js_secret=js_secret,
        ctx=client_ctx
    )

    do_sync_trans(
        zklay_client.web3,
        zklay_wallet
    )

    print(f"SYNC Done..")
