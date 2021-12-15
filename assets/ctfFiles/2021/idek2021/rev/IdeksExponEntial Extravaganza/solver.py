table = [b'$Yn@', b'%Yn@', b'/fTw', b'0fTw', b'1fTw', b'21aL', b'2fTw', b'31aL', b'3fTw', b'41aL', b'4fTw', b'51aL', b'5fTw', b'61aL', b'6fTw', b'71aL', b'7fTw', b'81aL', b'8fTw', b'91aL', b'9fTw', b':1aL', b':fTw', b';1aL', b';fTw', b'<1aL', b'<fTw', b'=1aL', b'=fTw', b'>1aL', b'>fTw', b'?1aL', b'?fTw', b'@1aL', b'@fTw', b'A1aL', b'AfTw', b'B1aL', b'BfTw', b'C1aL', b'CfTw', b'D1aL', b'DfTw', b'E1aL', b'EfTw', b'F1aL', b'FfTw', b'G1aL', b'GfTw', b'H1aL', b'HfTw', b'I1aL', b'IfTw', b'J1aL', b'JfTw', b'K1aL', b'KfTw', b'L1aL', b'LfTw', b'M1aL', b'MfTw', b'NfTw', b'OfTw', b'PfTw', b'QfTw', b'RfTw', b'SLzf', b'SfTw', b'TLzf', b'TfTw', b'ULzf', b'UfTw', b'VLzf', b'VfTw', b'WLzf', b'WfTw', b'XLzf', b'XfTw', b'YLzf', b'YfTw', b'ZLzf', b'ZfTw', b'[Lzf', b'[fTw', b'\Lzf', b'\fTw', b']Lzf', b']fTw', b'^Lzf', b'^fTw', b'_Lzf', b'_fTw', b'`Lzf', b'`fTw', b'a0%Y', b'aLzf', b'afTw', b'b0%Y', b'bLzf', b'bfTw', b'c0%Y', b'cLzf', b'cfTw', b'd0%Y', b'dLzf', b'dfTw', b'e0%Y', b'eLzf', b'efTw', b'f0%Y', b'fLzf', b'ffTw', b'g0%Y', b'gLzf', b'gfTw', b'h0%Y', b'hLzf', b'hfTw', b'i0%Y', b'iLzf', b'ifTw', b'j0%Y', b'jLzf', b'jfTw', b'k0%Y', b'kLzf', b'kfTw', b'l0%Y', b'lLzf', b'lfTw', b'm0%Y', b'm@M1', b'mLzf', b'mfTw', b'n0%Y', b'n@M1', b'nLzf', b'nfTw', b'o0%Y', b'o@M1', b'oLzf', b'ofTw', b'p0%Y', b'p@M1', b'pLzf', b'pfTw', b'q0%Y', b'q@M1', b'qLzf', b'qfTw', b'r0%Y', b'r@M1', b'rLzf', b'rfTw', b's0%Y', b's@M1', b'sLzf', b'sfTw', b't0%Y', b't@M1', b'tLzf', b'tfTw', b'u0%Y', b'u@M1', b'uLzf', b'ufTw', b'v0%Y', b'v@M1', b'vLzf', b'vfTw', b'w0%Y', b'w@M1', b'wLzf', b'wfTw', b'x0%Y', b'x@M1', b'xLzf', b'xfTw', b'y0%Y', b'y@M1', b'yLzf', b'yfTw', b'z0%Y', b'z@M1', b'zLzf', b'zfTw', b'{0%Y', b'{@M1', b'{Lzf', b'{fTw', b'|0%Y', b'|@M1', b'|Lzf', b'|fTw', b'}0%Y', b'}@M1', b'}Lzf', b'}fTw', b'~0%Y', b'~@M1', b'~Lzf', b'~fTw', ]

print(len(table))

print([x for x in table if x[0] == 112])

print([x for x in table if x[:2] == b"%Y"])

print([x for x in table if x[:2] == b"n@"])

print([x for x in table if x[:2] == b"M1"])

print([x for x in table if x[:2] == b"aL"])

print([x for x in table if x[:2] == b"zf"])

print(b"idek{" + b'p0%Y' + b"n@" + b"M1" + b"aL" + b"zfTw" + b"}")