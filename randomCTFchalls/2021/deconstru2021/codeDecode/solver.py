encrypt_key = '2nj-5x'
character_key = 'cxkl,_}o 4+tzrwe7ig9bfu5a-sy01.hpn628v3m{d:jq'

def create_encryption(character_key):
    charstring = "abcdefghijklmnopqrstuvwxyz1234567890 _+{}-,.:"
    final_encryption = {}
    for i, j in zip(charstring, character_key):
        final_encryption[i] = j
    return final_encryption

final_encryption = create_encryption(character_key)
res = dict((ord(v),k) for k,v in final_encryption.items())

ct = 'lgkma2bv1i0v}22lv19vuo19va2bvl2'

flag = ""
for letter in ct:
    flag += res[ord(letter)]

print(flag + "}")
#dsc{y0u_4r3_g00d_4t_wh4t_y0u_d0}