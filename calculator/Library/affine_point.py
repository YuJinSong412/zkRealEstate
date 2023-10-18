class AffinePoint():
    def __init__(self, x: int, y: int) -> None:
        self.x = x
        self.y = y
    def __str__(self) -> str:
        return "(" + str(self.x) + ", " + str(self.y) + ")"