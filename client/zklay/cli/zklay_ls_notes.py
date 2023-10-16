# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
# Copyright (c) 2021-2021 Zkrypto Inc.
# SPDX-License-Identifier: LGPL-3.0+

from zklay.cli.utils import load_zklay_address_secret, \
    open_zklay_wallet, load_zklay_audit_address_secret, create_zklayclient_and_zklaydesc, load_config_cache
from zklay.core.utils import EtherValue
from zklay.cli.debugger import print_wrapper, print_msg_box
from click import Context, command, option, pass_context


@command()
@option("--balance", default=True, is_flag=True, help="Show total balance")
@option("--spent", is_flag=True, help="Show spent notes")
@print_wrapper(num=0)
@pass_context
def ls_notes(ctx: Context, balance: bool, spent: bool) -> None:
    """
    List the set of notes owned by this wallet
    """

    client_ctx = ctx.obj

    zklay_client, _ = create_zklayclient_and_zklaydesc(
        client_ctx)

    try:
        js_secret = load_zklay_address_secret(client_ctx)
    except FileNotFoundError:
        js_secret = load_zklay_audit_address_secret(client_ctx)

    zklay_wallet = open_zklay_wallet(
        zklay_instance=zklay_client.zklay_instance,
        js_secret=js_secret,
        ctx=client_ctx
    )

    total = EtherValue(0)
    for addr, short_commit, value in zklay_wallet.note_summaries():
        msg = f"[ NOTE ] {short_commit}: value={value.ether()}, addr={addr}"
        print_msg_box(msg, width=91)
        total = total + value

    if balance:
        msg = f"TOTAL BALANCE: {total.ether()}"
        print_msg_box(msg, width=91)

    spent_title = f"SPENT NOTES"
    msg = ""
    for addr, short_commit, value in zklay_wallet.spent_note_summaries():
        msg += f"|| {short_commit}: value={value.ether()}, addr={addr} ||\n"

    print_msg_box(msg=msg, title=spent_title, width=91)
