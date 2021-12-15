from sage.modules.free_module_integer import IntegerLattice

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

L = 34
points = [4, 26, 22, 30, 1, 0, 2, 28, 23, 6, 25, 15, 5, 17, 14, 3, 13]
evaluations = [6218619148819094267912, 3239660278168289094170378865781537878483145039862, 13167423991006904868698304825721530103488567362, 362300164581366743933077318596814390341728710066538, 2912, 68, 1115908868222, 37269531510352347514290324712333731253807861642016, 56973337294691266392513915302684316231304471586, 3613524058959314538010460402, 889396341293302641051808753025749133146757798168, 43685960244566626421146033917835089685178, 9183044381254551882537188, 2694648608589552169772471076958756166751152, 4505915953382938147124977926390455694362, 529597204775372366, 392892826701163426612412172019222254476]

M1 = identity_matrix(L)
M2 = Matrix([list(map(lambda x: x^i, points)) for i in range(L)])
M = M1.augment(M2)

lb = [32] * L + evaluations
ub = [126] * L + evaluations

res, weights, _ = solve(M, lb, ub)

print("idek{", ''.join([chr(x) for x in res[:L]]), "}", sep="")

#idek{D1d_y0u_s34rch_7h1s_p0ly_6y_LLL???}