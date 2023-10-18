#!/usr/bin/env python
# -*- coding: utf-8 -*-
from mimc import MiMC7

#MiMC7 parameter : bn256_field_prime
#어떤 타원곡선인지 정해줘야하잔슴. 이것.
mimc7 = MiMC7(21888242871839275222246405745257275088548364400416034343698204186575808495617)

res = mimc7.hash(1,1)
expected = "2f81229fea90cc0b53ce8ea692be6993d9e6f8ea2fb56751b5d8cf4893f686fd" #
print(res.hex())

# 연구실에 에러 고치고 
# SKE -> dec를 Enc으로 고치고 
# tableLength를 13으로 바꾸고.(pk)
# make해봐서 error 안뜨는지 확인해야돼
