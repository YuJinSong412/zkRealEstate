from mimc import MiMC7

mimc7 = MiMC7(21888242871839275222246405745257275088548364400416034343698204186575808495617)

res = mimc7.hash(1,1)
expected = "2f81229fea90cc0b53ce8ea692be6993d9e6f8ea2fb56751b5d8cf4893f686fd" #
print(res.hex())
