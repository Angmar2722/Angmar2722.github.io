import torch
from torch import nn
import numpy as np
from functools import reduce
import base64
import numpy as np

model = torch.load(open("model.pth", "rb"))
w = list(model.values())[0]
w = np.matrix(w.numpy())
print(w)

given = "1VfgPsBNALxwfdW9yUmwPpnI075HhKg9bD5gPDLvjL026ho/xEpQvU5D4L3mOso+KGS7vvpT5T0FeN284inWPXyjaj7oZgI8I7q5vTWhOj7yFEq+TtmsPaYN7jxytdC9cIGwPti6ALw28Pm9eFZ/PkVBV75iV/U9NoP4PDoFn72+rI8+HHZivMwJvr2s5IQ+nASFvhoW2j1+uHE98MbuvdSNsT4kzrK82BGLvRrikz6oU66+oCGCPajDmzyg7Q69OjiDPvQtnjxwWw2+IB9ZPmaCLb4Mwhc+LimEPXXBQL75OQ8/ulQUvZZMsr3iO88+ZHz3viUgLT2U/d68C2xYPQ=="

print("Trying to decode to Y :")
r = base64.decodebytes(given.encode())
q = np.frombuffer(r, dtype=np.float32)
O = np.matrix(np.reshape(q, (8, 8)).astype(np.float32))
print(O)

""" Basically what's happening in nn.linear which we need to invert
ans = X
for i in range(7):
    ans = ans*w.T
print(ans)
"""
ans = O
winv = np.linalg.inv(w.T)
for i in range(7):
    ans = ans*winv

flagList = [i for i in np.array(ans.reshape((1, 64)))][0]

print(bytes([int(round(i)) for i in flagList]))
#b'buckeye{w41t_1ts_4ll_m4tr1x_mult1pl1cat10n????_4lwy4y5_h4s_b33n}'