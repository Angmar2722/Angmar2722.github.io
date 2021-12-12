from sage.modules.free_module_integer import IntegerLattice
from Crypto.Util.number import bytes_to_long, long_to_bytes

# Directly taken from rbtree's LLL repository
# From https://oddcoder.com/LOL-34c3/, https://hackmd.io/@hakatashi/B1OM7HFVI
def Babai_CVP(mat, target):
	M = IntegerLattice(mat, lll_reduce=True).reduced_basis
	G = M.gram_schmidt()[0]
	diff = target
	for i in reversed(range(G.nrows())):
		diff -=  M[i] * ((diff * G[i]) / (G[i] * G[i])).round()
	return target - diff

def solve(mat, lb, ub, weight = None):
	num_var  = mat.nrows()
	num_ineq = mat.ncols()

	max_element = 0 
	for i in range(num_var):
		for j in range(num_ineq):
			max_element = max(max_element, abs(mat[i, j]))

	if weight == None:
		weight = num_ineq * max_element

    # sanity checker
	if len(lb) != num_ineq:
		print("Fail: len(lb) != num_ineq")
		return

	if len(ub) != num_ineq:
		print("Fail: len(ub) != num_ineq")
		return

	for i in range(num_ineq):
		if lb[i] > ub[i]:
			print("Fail: lb[i] > ub[i] at index", i)
			return

    	# heuristic for number of solutions
	DET = 0

	if num_var == num_ineq:
		DET = abs(mat.det())
		num_sol = 1
		for i in range(num_ineq):
			num_sol *= (ub[i] - lb[i])
		if DET == 0:
			print("Zero Determinant")
		else:
			num_sol //= DET
			# + 1 added in for the sake of not making it zero...
			print("Expected Number of Solutions : ", num_sol + 1)

	# scaling process begins
	max_diff = max([ub[i] - lb[i] for i in range(num_ineq)])
	applied_weights = []

	for i in range(num_ineq):
		ineq_weight = weight if lb[i] == ub[i] else max_diff // (ub[i] - lb[i])
		applied_weights.append(ineq_weight)
		for j in range(num_var):
			mat[j, i] *= ineq_weight
		lb[i] *= ineq_weight
		ub[i] *= ineq_weight

	# Solve CVP
	target = vector([(lb[i] + ub[i]) // 2 for i in range(num_ineq)])
	result = Babai_CVP(mat, target)

	for i in range(num_ineq):
		if (lb[i] <= result[i] <= ub[i]) == False:
			print("Fail : inequality does not hold after solving")
			break
    
    	# recover x
	fin = None

	if DET != 0:
		mat = mat.transpose()
		fin = mat.solve_right(result)
	
	## recover your result
	return result, applied_weights, fin


from pwn import *

debug = False
r = remote("oooooo.quals.seccon.jp", 8000, level = 'debug' if debug else None)

r.recvuntil('M = ')
M = int(r.recvline().decode())

assert is_prime(M)

r.recvuntil('S = ')
S = int(r.recvline().decode())

k = (S - 79*sum(256^i for i in range(128))) * inverse_mod(32, M)
k = k % M

n = 129

MAT = [[0 for _ in range(n)] for _ in range(n)]
for i in range(n-1):
	MAT[i][i] = 1

for j in range(n-1):
	MAT[j][n-1] = 256^j

MAT[n-1][n-1] = M

MAT = Matrix(MAT)

lb = [0 for _ in range(n-1)] + [k]
ub = [1 for _ in range(n-1)] + [k]

res, weights, _ = solve(MAT, lb, ub)

msg = ''.join(["o" if x else "O" for x in res[:-1]])[::-1]

assert (bytes_to_long(msg.encode()) % M) == S

r.sendlineafter("message =", msg)

print(r.recvline())

#b'SECCON{Here_is_Huge-Huge_Island_yahhoOoOoOoOoOoO}\n'
