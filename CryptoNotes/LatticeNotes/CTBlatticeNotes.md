---
layout: page
title: Lattice Notes
---
<hr/>

<br/>

<br/>


## Section 3 - Equations

<br/>

Solution to challenge 1 (Hidden message; root polynomials) :

```python

#Hidden Message; Root Polynomials

'''
[1, -150, 4389, -43000, 131100]
[1, -177, 9143, -228909, 3264597, -28298835, 152170893, -502513551, 974729862, -995312448, 396179424]
[1, -196, 12537, -397764, 7189071, -77789724, 506733203, -1941451916, 4165661988, -4501832400, 1841875200]
[1, -153, 5317, -77199, 510274, -1269840]
[1, -194, 11791, -352754, 6011644, -61295576, 370272864, -1222050816, 1696757760]
[1, -169, 7702, -153082, 1477573, -6672349, 11042724]
[1, -202, 12936, -406082, 7170059, -74124708, 439747164, -1365683328, 1701311040]
[1, -206, 13919, -467924, 8975099, -102829454, 699732361, -2673468816, 4956440220, -2888395200]
'''


msg = ""
x = var('x', domain=ZZ)


eq = (x^4) - (150*x^3) + (4389 * x^2) - (43000 * x) + 131100
eq_sol = solve(eq==0, x)
print(f"Solution set for eq1 = {eq_sol}")
for v in eq_sol:
    if (32 <= v < 127):
        msg += chr(v)


eq = (x^10) - (177*x^9) + (9143*x^8) - (228909*x^7) + (3264597*x^6) - (28298835*x^5) + (152170893 * x^4) - (502513551 * x^3) + (974729862 * x^2) + (-995312448 * x^1) + (396179424)
eq_sol = solve(eq==0, x)
print(f"Solution set for eq2 = {eq_sol}")
for v in eq_sol:
    if (32 <= v < 127):
        msg += chr(v)


eq = (x^10) - (196*x^9) + (12537*x^8) - (397764*x^7) + (7189071*x^6) - (77789724*x^5) + (506733203 * x^4) - (1941451916 * x^3) + (4165661988 * x^2) + (-4501832400 * x^1) + (1841875200)
eq_sol = solve(eq==0, x)
print(f"Solution set for eq3 = {eq_sol}")
for v in eq_sol:
    if (32 <= v < 127):
        msg += chr(v)


eq = (x^5) - (153 * x^4) + (5317 * x^3) - (77199 * x^2) + (510274 * x) + (-1269840)
eq_sol = solve(eq==0, x)
print(f"Solution set for eq4 = {eq_sol}")
for v in eq_sol:
    if (32 <= v < 127):
        msg += chr(v)


eq = (1*x^8) - (194*x^7) + (11791*x^6) - (352754*x^5) + (6011644 * x^4) - (61295576 * x^3) + (370272864 * x^2) + (-1222050816 * x^1) + (1696757760)
eq_sol = solve(eq==0, x)
print(f"Solution set for eq5 = {eq_sol}")
for v in eq_sol:
    if (32 <= v < 127):
        msg += chr(v)


eq = (1*x^6) - (169*x^5) + (7702 * x^4) - (153082 * x^3) + (1477573 * x^2) + (-6672349 * x^1) + (11042724)
eq_sol = solve(eq==0, x)
print(f"Solution set for eq6 = {eq_sol}")
for v in eq_sol:
    if (32 <= v < 127):
        msg += chr(v)


eq = (1*x^8) - (202*x^7) + (12936*x^6) - (406082*x^5) + (7170059 * x^4) - (74124708 * x^3) + (439747164 * x^2) + (-1365683328 * x^1) + (1701311040)
eq_sol = solve(eq==0, x)
print(f"Solution set for eq6 = {eq_sol}")
for v in eq_sol:
    if (32 <= v < 127):
        msg += chr(v)


eq = (1*x^9) - (206*x^8) + (13919*x^7) - (467924*x^6) + (8975099 * x^5) - (102829454 * x^4) + (699732361 * x^3) + (-2673468816 * x^2) + (4956440220* x^1) - (2888395200)
eq_sol = solve(eq==0, x)
print(f"Solution set for eq6 = {eq_sol}")
for v in eq_sol:
    if (32 <= v < 127):
        msg += chr(v)


print(msg)
#sonorous


```

<br/>

<br/>

## Section 5 - Matrices

<br/>

If the process of **Gaussian elimination** is operated on an augmented matrix's row, the matrix is said to be in **row echelon form**. This occurs when :

- All rows consisting of only zeroes are at the bottom
- The leading coefficient of a nonzero row (the first nonzero entry in the row) is always strictly to the right of the leading coefficient above it.
- Leading coefficient must be 1 (according to some texts)

The matrix below is in row echelon form but not reduced row echelon form (Note that the third column contains 2 which is a leading coefficient but is not 1. This still fits some definitions of a matrix in row echelon form) :

$$ \left[
\begin{array}{cccc|c}
1 & a_0 & a_1 & a_2 & a_3 \\ 
0 & 0 & 2 & a_2 & a_5 \\
0 & 0 & 0 & 1 & a_6
\end{array}
\right] $$

A **matrix is in reduced row echelon form** if the following conditions are satisfied :

- It is in row echelon form
- The leading entry in each nonzero row is a 1 (known as a leading 1)
- Each column containing a leading 1 has zeroes in all its other entries. 

The matrix below is in reduced row echelon form :

$$ \left[
\begin{array}{cccc|c}
1 & 0 & a_1 & 0 & b_1 \\ 
0 & 1 & a_2 & 0 & b_2 \\
0 & 0 & 0 & 1 & b_3
\end{array}
\right] $$

We can transform an augmented matrix into a matrix in reduced row echelon form because we can make the following observations:

- Swapping the positions of two equations doesn’t affect the solution of the system
of the linear equations.
- Multiplying the equation by a nonzero number doesn’t affect the solution of the
system of the linear equations.
- Adding one randomly chosen equation to another randomly chosen equation doesn’t
affect the solution of the system of the linear equations

Using row operations to convert a matrix into reduced row echelon form is sometimes called **Gauss–Jordan elimination**.

<br/>

### Challenge 3 (System of equations puzzle)

We are given the following sets of systems of linear equations :

$$
\left\{ 
\begin{array}{c}
115b + 111h + 108f = 2209 \\ 
118b + 101h + 115f = 2214 \\
111b + 114h + 116f = 2286
\end{array}
\right. 
$$


$$
\left\{ 
\begin{array}{c}
97q + 100m + 100a = 1582 \\ 
111q + 110m + 101a = 1748 \\
116q + 111m + 101a = 1786
\end{array}
\right. 
$$


$$
\left\{ 
\begin{array}{c}
97r + 99n + 104t = 910 \\ 
108r + 101n + 116t = 1005 \\
116r + 101n + 114t = 1019
\end{array}
\right. 
$$

Using Sage to convert the systems of linear equations into augmented matrices and further into reduced row echelon form we obtain :

```python

'''
115*b + 111*h + 108*f = 2209
118*b + 101*h + 115*f = 2214
111*b + 114*h + 116*f = 2286
97*q + 100*m + 100*a = 1582
111*q + 110*m + 101*a = 1748
116*q + 111*m + 101*a = 1786
97*r + 99*n + 104*t = 910
108*r + 101*n + 116*t = 1005
116*r + 101*n + 114*t = 1019
'''

A = matrix([[115,111,108],[118,101,115],[111,114,116]])
b = vector([2209,2214,2286])
B = A.augment(b)
print(B.rref())

'''
[1 0 0 4]
[0 1 0 7]
[0 0 1 9]
'''

A = matrix([[97,100,100],[111,110,101],[116,111,101]])
b = vector([1582,1748,1786])
B = A.augment(b)
print(B.rref())

'''
[1 0 0 6]
[0 1 0 8]
[0 0 1 2]
'''
A = matrix([[97,99,104],[108,101,116],[116,101,114]])
b = vector([910,1005,1019])
B = A.augment(b)
print(B.rref())

'''
[1 0 0 3]
[0 1 0 1]
[0 0 1 5]
'''

'''
Hence b = 4, h = 7, f = 9, q = 6, m = 8, a = 2, r = 3, n = 1, t = 5
'''

```

In mathematics, a binary operation is commutative if changing the order of the operands does not change the result. The associative property of an expression containing two or more occurrences of the same operator states that the order operations are performed in does not affect the final result, as long as the order of terms does not change.
