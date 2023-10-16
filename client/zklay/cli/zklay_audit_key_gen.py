# Copyright (c) 2021-2021 Zkrypto Inc.
#
# SPDX-License-Identifier: LGPL-3.0+

from zklay.core.zklay_audit_address import ZklayAuditAddress
from zklay.cli.utils import get_zklay_audit_address_file, pub_address_file, \
    write_zklay_audit_address_secret, write_zklay_audit_address_public, load_eth_address,\
    load_eth_private_key, open_web3_from_ctx, create_zklayclient_and_zklaydesc
from click import command, pass_context, ClickException, Context, option
from typing import Optional
from os.path import exists
from zklay.core.utils import EtherValue, get_zklay_config_file_path
from zklay.cli.debugger import print_wrapper, print_value


@command()
@option("--eth-addr", help="Sender eth address or address filename")
@option("--eth-private-key", help="Sender's eth private key file")
@option("--token-address", help="Address of token contract (if used)")
@option("--register-gas", type=int, help="Maximum gas, in Wei")
@print_wrapper(num=0)
@pass_context
def audit_key_gen(
        ctx: Context,
        eth_addr: Optional[str],
        eth_private_key: Optional[str],
        token_address: str,
        register_gas: Optional[int]) -> None:
    """
    Generate a new auditor secret key and public address
    """

    eth_address = load_eth_address(eth_addr)
    eth_private_key_data = load_eth_private_key(eth_private_key)
    client_ctx = ctx.obj
    web3 = open_web3_from_ctx(client_ctx)

    addr_file = get_zklay_audit_address_file(client_ctx)
    if exists(addr_file):
        raise ClickException(f"auditAddress file {addr_file} exists")

    pub_addr_file = pub_address_file(addr_file)
    if exists(pub_addr_file):
        raise ClickException(f"auditAddress pub file {pub_addr_file} exists")

    zklay_audit_address = ZklayAuditAddress.generate_keypair(client_ctx)
    write_zklay_audit_address_public(zklay_audit_address.apk, pub_addr_file)
    print(f"\nPublic AuditAddress written to {pub_addr_file}")

    write_zklay_audit_address_secret(zklay_audit_address.ask, addr_file)
    print(f"Secret AuditAddress written to {addr_file}\n")

    print_value(eth_address, name="eth_address", func_name="audit_key_gen")

    zklay_client, _ = create_zklayclient_and_zklaydesc(
        client_ctx)

    tx_hash = zklay_client.registerAuditor(
        audit_public_key=zklay_audit_address.apk.apk,
        auditor_eth_address=eth_address,
        auditor_eth_private_key=eth_private_key_data,
        tx_value=EtherValue(0))

    print_value(tx_hash, name="tx_hash", func_name="audit_key_gen")
