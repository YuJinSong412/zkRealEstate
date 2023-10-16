from unittest import TestCase
from zklay.core.montgomery_curve import *
from zklay.core.context import ClientConfig
from zklay.core.utils import load_default_config


class TestMontgomeryCurve(TestCase):
    def test_coco_base_mult(self, client_ctx: ClientConfig):
        ret = base_point_mult(
            client_ctx,
            1276549805487041174259271520830089050275768397924723526675722207986282541840)  # scalar value
        self.assertEqual(
            ret,
            15284783757869051634865025629715554078060081392940608974342227058558028584231   # expected
        )

    def test_bandersnatch_base_mult(self, client_ctx: ClientConfig):
        ret = base_point_mult(
            client_ctx,
            2385595980973977154417438842224813584784754789495865018346238157024331491394)  # scalar value
        self.assertEqual(
            ret,
            10149645631545576797348864604084417680111607339339251215927854559121919341224   # expected
        )

    def test_coco_scalar_mult(self, client_ctx: ClientConfig):
        ret = multscalar(
            client_ctx,
            3834214753426150746019413714964873074901850005455223590905108748880626058776,  # basepoint_x
            1276549805487041174259271520830089050275768397924723526675722207986282541840)  # scalar value
        self.assertEqual(
            ret,
            # expected
            15747567559011417980034824653321284305120204358974147930069472608189629825243
        )

    def test_bandersnatch_scalar_mult(self, client_ctx: ClientConfig):
        ret = multscalar(
            client_ctx,
            10812954262002421791776604172027613967961460457280937888644276649296688403542,  # basepoint_x
            1919022583759269308272347025826117491857694503782308602552351500717617024762)  # scalar value
        self.assertEqual(
            ret,
            # expected
            7238033329307861907420494178242671240611336740263022739516413041537597975161
        )


if __name__ == "__main__":
    client_ctx = load_default_config()
    TestMontgomeryCurve().test_coco_base_mult(client_ctx)
    TestMontgomeryCurve().test_coco_scalar_mult(client_ctx)
    # client_ctx.ec = 'BLS12-381'
    # TestMontgomeryCurve().test_bandersnatch_base_mult(client_ctx)
    # TestMontgomeryCurve().test_bandersnatch_scalar_mult(client_ctx)
