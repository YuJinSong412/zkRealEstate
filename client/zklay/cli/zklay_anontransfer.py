# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
# Copyright (c) 2021-2021 Zkrypto Inc.
# SPDX-License-Identifier: LGPL-3.0+

from zklay.cli.utils import load_eth_address, \
    load_eth_private_key, load_zklay_audit_address_public, \
    load_zklay_address_secret, load_zklay_address_public, load_zklay_address_public,\
    create_zklayclient_and_zklaydesc, open_zklay_wallet
from zklay.cli.constants import ETH_ADDRESS_DEFAULT
from zklay.core.constants import CIRCUIT
from zklay.core.utils import EtherValue, Pocket
from click import command, option, pass_context, Context
from typing import Optional
from zklay.cli.debugger import print_wrapper, print_value
from typing import Any


@command()
@option("--v_in", default="0", help="Public input value pv ")
@option("--v_out", default="0", help="Public output value pv' ")
@option("--rev", default="", help="Receiver path (ex. ../bob) ")
@option("--v_priv", required=True, help="sending amount dv' ")
@option("--circuit", required=True, default= CIRCUIT,help="Circuit Name",show_default=True)
@option("--eth-addr", help="Sender's eth address or address filename")
@option("--eth-private-key", help="Sender's eth private key file")
@print_wrapper(num=0)
@pass_context
def anontransfer(
        ctx: Context,
        v_in: str,
        v_out: str,
        rev: str,
        v_priv: str,
        circuit: Optional[str],
        eth_addr: Optional[str],
        eth_private_key: Optional[str]) -> None:
    """
    Trigger transfer function
    """
    client_ctx = ctx.obj

    print(" {0: <20}:   {1}".format('Public input', v_in))
    print(" {0: <20}:   {1}".format('Public output', v_out))
    print(" {0: <20}:   {1}".format('Hidden transfer amount', v_priv))

    vin_pub = EtherValue(v_in)
    vout_pub = EtherValue(v_out)
    vpriv_pub = EtherValue(v_priv)

    pocket = Pocket(
        v_priv=vpriv_pub,
        v_in=vin_pub,
        v_out=vout_pub
    )

    eth_address = load_eth_address(eth_addr)
    eth_private_key_data = load_eth_private_key(eth_private_key)

    zklay_client, zklay_desc = create_zklayclient_and_zklaydesc(
        client_ctx)

    auditor_pub = load_zklay_audit_address_public(client_ctx)  #  TODO

    sender_priv = load_zklay_address_secret(client_ctx)  # sk
    sender_pub = load_zklay_address_public(client_ctx)  # pk
    receiver_pub = load_zklay_address_public(client_ctx, rev)  # pk'

    receiver_eth_address = load_eth_address(rev+"/"+ETH_ADDRESS_DEFAULT)

    zklay_wallet = open_zklay_wallet(
        zklay_instance=zklay_client.zklay_instance,
        js_secret=sender_priv,
        ctx=client_ctx
    )

    trans_param = zklay_client.create_trans_args(
        circuit_name=circuit,
        zklay_wallet=zklay_wallet,
        auditor_pub=auditor_pub,
        sender_pub=sender_pub,
        sender_priv=sender_priv,
        receiver_pub=receiver_pub,
        pocket=pocket,
        toEoA=receiver_eth_address)

    tx_hash = zklay_client.anontransfer(
        trans_param=trans_param,
        sender_eth_address=eth_address,
        sender_eth_private_key=None,
        tx_value=vin_pub)

    print_value(tx_hash, name="tx_hash", func_name="anotransfer")
