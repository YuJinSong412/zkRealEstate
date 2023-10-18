from __future__ import annotations
from Library.affine_point import AffinePoint
from Library.utils import modular_sqrt
from Library.context import ClientConfig
from typing import List


class CurveParameters():

    def __init__(self, client_ctx: ClientConfig) -> None:

        # COCO
        if client_ctx.ec == "BN256":
            self.field_prime = 21888242871839275222246405745257275088548364400416034343698204186575808495617
            self.generator = 10398164868948269691505217409040279103932722394566360325611713252123766059173
            self.coeff_A = 126932
            self.coeff_B = 1

        # Bandersnatch
        elif client_ctx.ec == "BLS12-381":
            self.field_prime = 52435875175126190479447740508185965837690552500527637822603658699938581184513
            self.generator = 46937548361816886563847943541604243346921840144669283775907349952397536703416
            self.coeff_A = 29978822694968839326280996386011761570173833766074948509196803838190355340952
            self.coeff_B = 21732574493545642452588025716306585039145419364997213261322953924237652797223


class MontgomeryCurve():

    def __init__(self, curve_params: CurveParameters) -> None:
        self.field_prime = curve_params.field_prime
        self.generator = curve_params.generator
        self.coeff_A = curve_params.coeff_A
        self.coeff_B = curve_params.coeff_B

    def preprocess_computation(self, p: AffinePoint, exp: int) -> List[int]:
        precomputed_table = [p]

        for _ in range(exp.bit_length()):
            base_point = precomputed_table[-1]
            precomputed_table.append(self.double_affine_point(base_point))

        return precomputed_table

    def multiply(self, precomputed_table: List[int], exp: int) -> AffinePoint:
        exp_bit = format(exp, 'b')[::-1]  # little-endian form
        result = precomputed_table[-1]
        for i, p in enumerate(precomputed_table[:-1]):
            if exp_bit[i] == '1':
                result = self.add_affine_point(result, p)

        result = self.sub_affine_point(result, precomputed_table[-1])

        return result

    def preprocess_base_point(self, p: AffinePoint) -> AffinePoint:
        new_x = p.x % self.field_prime
        new_y = p.y % self.field_prime

        return AffinePoint(new_x, new_y)

    def double_affine_point(self, p: AffinePoint) -> AffinePoint:
        tmp_x = (3 * p.x ** 2 + 2 * p.x * self.coeff_A + 1) % self.field_prime
        l1 = self.field_division(tmp_x, p.y * 2 * self.coeff_B)
        b_l2 = (l1 ** 2 * self.coeff_B) % self.field_prime

        new_x = (b_l2 - self.coeff_A - (2 * p.x)) % self.field_prime
        new_y = ((p.x * 3 + self.coeff_A - b_l2) * l1 - p.y) % self.field_prime

        return AffinePoint(new_x, new_y)

    def add_affine_point(self, p1: AffinePoint, p2: AffinePoint) -> AffinePoint:
        diff_y = (p1.y - p2.y) % self.field_prime
        diff_x = (p1.x - p2.x) % self.field_prime
        q = self.field_division(diff_y, diff_x)
        b_q2 = (q ** 2 * self.coeff_B) % self.field_prime
        new_x = (b_q2 - self.coeff_A - p1.x - p2.x) % self.field_prime
        new_y = (q * (p1.x - new_x) - p1.y) % self.field_prime

        return AffinePoint(new_x, new_y)

    def sub_affine_point(self, p1: AffinePoint, p2: AffinePoint) -> AffinePoint:
        neg_p2 = AffinePoint(p2.x, -p2.y % self.field_prime)

        return self.add_affine_point(p1, neg_p2)

    def field_division(self, a: int, b: int) -> int:
        return a * pow(b, -1, self.field_prime) % self.field_prime

    def check_scalar(self, scalar: int) -> bool:
        return scalar.bit_length() <= self.field_prime

    def compute_y_coordinate(self, x: int) -> int:
        b_y_squared = (x ** 3 + self.coeff_A * x ** 2 + x) % self.field_prime
        y_squared = self.field_division(b_y_squared, self.coeff_B)
        y = modular_sqrt(y_squared, self.field_prime)

        return y

    def assert_valid_point_on_EC(self, p: AffinePoint) -> None:
        lhs = (p.y ** 2 * self.coeff_B) % self.field_prime
        rhs = (p.x ** 3 + self.coeff_A * p.x ** 2 + p.x) % self.field_prime

        if lhs != rhs:
            print("lhs, rhs:", lhs, rhs)
        assert( lhs == rhs )

    def compute_scalar_mul(self, p: AffinePoint, exp: int) -> AffinePoint:
        base_point = self.preprocess_base_point(p)
        precomputed_table = self.preprocess_computation(base_point, exp)
        output = self.multiply(precomputed_table, exp)

        return output

    def equal(self, p1, p2) -> bool :
        assert p1.x == p2.x
        assert p1.y == p2.y


def multscalar(client_ctx: ClientConfig, base_x: int, exp: int):
    curve_params = CurveParameters(client_ctx)
    curve = MontgomeryCurve(curve_params)
    base_y = curve.compute_y_coordinate(base_x)
    base_point = AffinePoint(base_x, base_y)
    curve.assert_valid_point_on_EC(base_point)
    result = curve.compute_scalar_mul(base_point, exp)
    curve.assert_valid_point_on_EC(result)

    return curve.compute_scalar_mul(base_point, exp).x


def base_point_mult(client_ctx: ClientConfig, exp: int):
    curve_params = CurveParameters(client_ctx)
    curve = MontgomeryCurve(curve_params)
    base_y = curve.compute_y_coordinate(curve.generator)
    base_point = AffinePoint(curve.generator, base_y)
    curve.assert_valid_point_on_EC(base_point)
    result = curve.compute_scalar_mul(base_point, exp)
    curve.assert_valid_point_on_EC(result)

    return curve.compute_scalar_mul(base_point, exp).x
