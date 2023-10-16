
from unittest import TestCase
from zklay.core.context import ClientConfig
import zklay.cli.constants as cli_constants
import zklay.core.constants as core_constants
from zklay.core.montgomery_curve import *
from zklay.core.affine_point import AffinePoint


class TestMontgomeryCurve(TestCase):

    def test_BN256(self):
        client_ctx = ClientConfig(
            env = cli_constants.ETH_NETWORK_DEFAULT,
            instance_file = cli_constants.INSTANCE_FILE_DEFAULT,
            token_instance_file = cli_constants.TOKEN_INSTANCE_FILE_DEFAULT,
            address_file = cli_constants.ZKLAY_SECRET_ADDRESS_FILE_DEFAULT,
            audit_address_file =cli_constants.ZKLAY_AUDIT_SECRET_ADDRESS_FILE_DEFAULT,
            wallet_dir = cli_constants.WALLET_DIR_DEFAULT,
            depth = core_constants.DEPTH_TYPE[2],
            hash = cli_constants.HASH_TYPE[1],
            zksnark = core_constants.GROTH16_ZKSNARK,
            ec = core_constants.ELLIPTIC_CURVE_TYPE[0] # bls12-381
        )
        base_x = base_point_mult(client_ctx, 5)
        ret = multscalar(client_ctx, base_x, 5)

        self.assertEqual(
            ret,
            45194668461132336457433454732943324729908639266258266712660172047979076344559
        )

        cp = CurveParameters(client_ctx)
        bn256_curve = MontgomeryCurve(cp)
        base_y = bn256_curve.compute_y_coordinate(base_x)

        base_p = AffinePoint(
            x = base_x,
            y = base_y
        )

        db_base_p = bn256_curve.double_affine_point(base_p)
        p1 = bn256_curve.double_affine_point(db_base_p) 

        p2 = bn256_curve.add_affine_point(bn256_curve.add_affine_point(bn256_curve.double_affine_point(base_p),base_p), base_p)

        bn256_curve.assert_valid_point_on_EC(p1)
        bn256_curve.assert_valid_point_on_EC(p2)
        bn256_curve.equal(p1, p2)

        p3 = bn256_curve.add_affine_point(
            bn256_curve.compute_scalar_mul(base_p,9),
            bn256_curve.compute_scalar_mul(base_p,5)
        )

        p4 = bn256_curve.add_affine_point(
            bn256_curve.compute_scalar_mul(base_p,12),
            bn256_curve.compute_scalar_mul(base_p,2)
        )

        bn256_curve.assert_valid_point_on_EC(p3)
        bn256_curve.assert_valid_point_on_EC(p4)
        bn256_curve.equal(p3, p4)



    def test_BLS12381(self):
        client_ctx = ClientConfig(
            env = cli_constants.ETH_NETWORK_DEFAULT,
            instance_file = cli_constants.INSTANCE_FILE_DEFAULT,
            token_instance_file = cli_constants.TOKEN_INSTANCE_FILE_DEFAULT,
            address_file = cli_constants.ZKLAY_SECRET_ADDRESS_FILE_DEFAULT,
            audit_address_file =cli_constants.ZKLAY_AUDIT_SECRET_ADDRESS_FILE_DEFAULT,
            wallet_dir = cli_constants.WALLET_DIR_DEFAULT,
            depth = core_constants.DEPTH_TYPE[2],
            hash = cli_constants.HASH_TYPE[1],
            zksnark = core_constants.GROTH16_ZKSNARK,
            ec = core_constants.ELLIPTIC_CURVE_TYPE[1] # bls12-381
        )
        
        base_x = base_point_mult(client_ctx, 5)
        ret = multscalar(client_ctx, base_x, 5)

        self.assertEqual(
            ret,
            12722252743179969538623250263883855869918249796816529356199934851719912962673
        )

        cp = CurveParameters(client_ctx)
        bls12381 = MontgomeryCurve(cp)
        base_y = bls12381.compute_y_coordinate(base_x)

        base_p = AffinePoint(
            x = base_x,
            y = base_y
        )

        db_base_p = bls12381.double_affine_point(base_p)
        p1 = bls12381.double_affine_point(db_base_p) 

        p2 = bls12381.add_affine_point(bls12381.add_affine_point(bls12381.double_affine_point(base_p),base_p), base_p)

        bls12381.assert_valid_point_on_EC(p1)
        bls12381.assert_valid_point_on_EC(p2)
        bls12381.equal(p1, p2)

        p3 = bls12381.add_affine_point(
            bls12381.compute_scalar_mul(base_p,9),
            bls12381.compute_scalar_mul(base_p,5)
        )

        p4 = bls12381.add_affine_point(
            bls12381.compute_scalar_mul(base_p,12),
            bls12381.compute_scalar_mul(base_p,2)
        )

        bls12381.assert_valid_point_on_EC(p3)
        bls12381.assert_valid_point_on_EC(p4)
        bls12381.equal(p3, p4)


if __name__ == "__main__":
    TestMontgomeryCurve().test_BN256()
    TestMontgomeryCurve().test_BLS12381()
