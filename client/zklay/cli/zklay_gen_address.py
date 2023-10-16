# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
# Copyright (c) 2021-2021 Zkrypto Inc.
# SPDX-License-Identifier: LGPL-3.0+

from zklay.core.zklay_address import ZklayAddress
from zklay.cli.utils import get_zklay_address_file, pub_address_file, \
    write_zklay_address_secret, write_zklay_address_public, \
    load_zklay_audit_address_public, load_eth_private_key, load_eth_address, \
    create_zklayclient_and_zklaydesc
from zklay.cli.debugger import print_wrapper, print_value
from click import command, pass_context, ClickException, Context, option
from typing import Optional
from os.path import exists
from zklay.core.utils import EtherValue, int256_to_bytes

default_value: int = 100000


@command()
@option("--eth-addr", help="Sender eth address or address filename")
@option("--eth-private-key", help="Sender's eth private key file")
@print_wrapper(num=0)
@pass_context
def gen_address(
    ctx: Context,
    eth_addr: Optional[str],
    eth_private_key: Optional[str],
) -> None:
    """
    Generate a new Zklay secret key and public address
    """
    eth_address = load_eth_address(eth_addr)
    eth_private_key_data = load_eth_private_key(eth_private_key)
    client_ctx = ctx.obj

    addr_file = get_zklay_address_file(client_ctx)
    if exists(addr_file):
        raise ClickException(f"ZklayAddress file {addr_file} exists")

    pub_addr_file = pub_address_file(addr_file)
    if exists(pub_addr_file):
        raise ClickException(f"ZklayAddress pub file {pub_addr_file} exists")

    zklay_address = ZklayAddress.generate_keypair(client_ctx)

    write_zklay_address_secret(zklay_address.usk, addr_file)
    print(f"Secret ZklayAddress written to {addr_file}")

    write_zklay_address_public(zklay_address.upk, pub_addr_file)
    print(f"Public ZklayAddress written to {pub_addr_file}")

    addr = int256_to_bytes(zklay_address.upk.addr)

    print_value(addr.hex(), name="addr", func_name="gen_address")

    zklay_client, _ = create_zklayclient_and_zklaydesc(
        client_ctx)

    tx_hash = zklay_client.registerUser(
        addr=addr,
        user_eth_address=eth_address,
        user_eth_private_key=eth_private_key_data,
        tx_value=EtherValue(0))

    print_value(tx_hash, name="tx_hash", func_name="registerUser")
