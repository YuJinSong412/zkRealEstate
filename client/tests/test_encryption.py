#!/usr/bin/env python3

# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from zklay.core.zklay_audit_address import ZklayAuditAddress
from zklay.core.zklay_address import ZklayAddress
from zklay.core.context import ClientConfig
import zklay.cli.constants as cli_constants
import zklay.core.constants as core_constants
from zklay.core.zklay_encryption import SymmetricKeyEncryptionSystem, PublicKeyEncryptionSystem
from unittest import TestCase

class TestEncryption(TestCase):
    def __init__(self) -> None:
        super().__init__()
        self.client_ctx = ClientConfig(
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
        self.auditor = ZklayAuditAddress.generate_keypair(self.client_ctx)
        self.user = ZklayAddress.generate_keypair(self.client_ctx)

    def test_symmetric_key_encryption(self) -> None :
        senc = SymmetricKeyEncryptionSystem(self.client_ctx, self.user.usk.usk)
        plaintext = int("2af03b0046e15e8f24cdf4515d07cdbc5546ccd73fef162d453c55c6a635f6ee",16)

        ciphertext = senc.encrypt(plaintext)

        dec_msg = senc.decrypt(ciphertext)

        self.assertEqual(
            plaintext,
            dec_msg
        )
    
    def test_public_key_encryption(self) -> None:
        penc = PublicKeyEncryptionSystem(self.client_ctx, self.user.usk.usk)

        msg = [
            int("2af03b0046e15e8f24cdf4515d07cdbc5546ccd73fef162d453c55c6a635f6ee",16),
            int("0x2825a2f1be85b53051e3affe3f3d3f68ebc52e7c3adc18d6e869630b67fabf3d",16),
            int("0x094d9300fbef14f29e7c0de15ac229a719cae308cd100f9f06bc540ad1369bec",16)
        ]

        ciphertext, aux_0, aux_1 = penc.encrypt(
            self.auditor.apk,
            self.user.upk,
            msg[0],
            msg[1],
            msg[2]            
        )

        dec_msg = penc.decrypt(ciphertext)

        self.assertEqual(
            msg[0],
            dec_msg[0]
        )

        self.assertEqual(
            msg[1],
            dec_msg[1]
        )

        self.assertEqual(
            msg[2],
            dec_msg[2]
        )


if __name__ == "__main__" :
    TestEncryption().test_symmetric_key_encryption()
    TestEncryption().test_public_key_encryption()
