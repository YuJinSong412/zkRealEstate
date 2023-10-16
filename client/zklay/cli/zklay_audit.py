# Copyright (c) 2021-2021 Zkrypto Inc.
#
# SPDX-License-Identifier: LGPL-3.0+
from zklay.cli.utils import get_zklay_audit_address_file, load_zklay_audit_address,  \
    create_zklayclient_and_zklaydesc, get_user_audit
from zklay.cli.debugger import print_wrapper
from click import command, pass_context, ClickException, Context, option
from typing import Optional
from os.path import exists
import os


@command()
@option("--path", help="Path to read two files that are are auditor's private key and instance file")
@option("--tx_hash", help="tx hash value")
@print_wrapper(num=0)
@pass_context
def audit(
        ctx: Context,
        path: Optional[str],
        tx_hash: Optional[str]) -> None:

    client_ctx = ctx.obj

    if path:
        os.chdir(path)

    zklay_client, _ = create_zklayclient_and_zklaydesc(
        client_ctx)

    is_auditor = get_zklay_audit_address_file(client_ctx)

    if exists(is_auditor) == False:
        raise ClickException(f"AuditAddress file {is_auditor} does not exist")

    auditor = load_zklay_audit_address(client_ctx)

    get_user_audit(client_ctx, auditor, zklay_client, tx_hash)
