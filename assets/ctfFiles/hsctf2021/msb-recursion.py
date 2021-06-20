import random,sys,math,time,gmpy
from Crypto.Util import number
from random import randint

sys.setrecursionlimit(2500)

# remove random bits from prime
def removebits(t,delta):
	i=1
	w=t[0]
	known=(delta*len(t))/100
	unknown=len(t)-known
	while i < len(t):
		pos=[t[i]]*delta + ['b']*(100-delta)
		c=random.choice(pos)
		if (unknown>0) and (c!=t[i]):
			unknown-=1
			w = w + 'b'
		else:
			w = w + str(c)
		i+=1
	return w


l=int(sys.argv[1])
delta=int(sys.argv[2])
option=int(sys.argv[3])


nump=number.getPrime(l, randfunc=None)		# generate Prime number of bit length L as p
numq=number.getPrime(l, randfunc=None)		# generate Prime number of bit length L as q
NN=nump*numq								# generate N = p.q

N=str(bin(NN))[2:]							# generate modulus of 2*L bits
binp=str(bin(nump))[2:]						# generate binary representation of p 
binq=str(bin(numq))[2:]						# generate binary representation of q
n=len(binp)									
p=removebits(binp,delta)					# generate experimental p by removing random bits of p with probability delta
q=removebits(binq,delta)					# generate experimental q by removing random bits of q with probability delta


h=(len(p)+len(q))-len(N)
while h>0:
	N='0'+N									# prefix zeros to make bit length of N equal to twice of bit length of p
	h-=1

phiN=(nump-1)*(numq-1)						# generate phi(N)

ee=65537
numd=gmpy.invert(ee,phiN)					# generate d as multiplicative inverse of e in mod phi(N)
bin_d=bin(numd)[2:]							# generate binary representation of d
d=removebits(bin_d,delta)					# generate experimental d by removing random bits of d with probability delta
k=(ee*numd)/phiN							# generate k as in e.d = k. phi(N) + 1
m=len(d)									# number of bits in d is stored in m
Nr=(k*(NN+1)+1) 
mn2=(ee*(2**(m-n)))

numdp=pow(numd,1,(nump-1))					# generate dp = d mod (p-1)
bindp=bin(numdp)[2:]						# store binary representation of dp
numdq=pow(numd,1,(numq-1))					# generate dq = d mod (q-1)
bindq=bin(numdq)[2:]						# store binary representation of dq
kp=(ee*numdp)/(nump-1)						# generate kp as in e.dp = kp. (p-1) +1
kq=(ee*numdq)/(numq-1)						# generate kp as in e.dq = kq. (q-1) +1
t=len(bindp)									# number of bits in dp is stored in t
c=len(bindq)									# number of bits in dq is stored in c

l=len(binp)-t
while l>0:					# padding of '0' to make dp of n-bits
	bindp='0'+bindp
	l-=1


l=len(binq)-c

while l>0:					# padding of '0' to make dq of n-bits
	bindq='0'+bindq
	l-=1
	
dq=removebits(bindq,delta)					# generate experimental dq by removing random bits of dq with probability delta
dp=removebits(bindp,delta)					# generate experimental dp by removing random bits of dp with probability delta

start=time.time()							# recording start time of algorithm
keylen=0									# number of candidate keys

# array of possible values of i-th bit of 5 components in CRT-RSA
possible_values_ALL= [ ['0', '0', '0', '0', '0'],
    ['0', '0', '0', '0', '1'],
    ['0', '0', '0', '1', '0'],
    ['0', '0', '0', '1', '1'],
    ['0', '0', '1', '0', '0'],
    ['0', '0', '1', '0', '1'],
    ['0', '0', '1', '1', '0'],
    ['0', '0', '1', '1', '1'],
    ['0', '1', '0', '0', '0'],
    ['0', '1', '0', '0', '1'],
    ['0', '1', '0', '1', '0'],
    ['0', '1', '0', '1', '1'],
    ['0', '1', '1', '0', '0'],
    ['0', '1', '1', '0', '1'],
    ['0', '1', '1', '1', '0'],
    ['0', '1', '1', '1', '1'],
    ['1', '0', '0', '0', '0'],
    ['1', '0', '0', '0', '1'],
    ['1', '0', '0', '1', '0'],
    ['1', '0', '0', '1', '1'],
    ['1', '0', '1', '0', '0'],
    ['1', '0', '1', '0', '1'],
    ['1', '0', '1', '1', '0'],
    ['1', '0', '1', '1', '1'],
    ['1', '1', '0', '0', '0'],
    ['1', '1', '0', '0', '1'],
    ['1', '1', '0', '1', '0'],
    ['1', '1', '0', '1', '1'],
    ['1', '1', '1', '0', '0'],
    ['1', '1', '1', '0', '1'],
    ['1', '1', '1', '1', '0'],
    ['1', '1', '1', '1', '1'] ]


# array of possible values of i-th bit of 3 components in RSA
possible_values_PQD= [ ['0','0', '0'],
                      ['0','0', '1'],
                      ['0','1', '0'],
                      ['0','1', '1'],
                      ['1','0', '0'],
                      ['1','0', '1'],
                      ['1','1', '0'],
                      ['1','1', '1'],]


def Backtrack_factor_msb_pq_recursion(p1,q1,i):
	#print i
	global start
	if int(time.time()-start) > 300: 		# exit if time exceeded 5 minutes
		sys.exit()
	if (i+1)==n: 				# Check if candidates of p and q are factors of N
		global keylen
		keylen+=1
		if (((p1+'1')==binp) or ((q1+'1')==binq)):
			print ((time.time() - start)),keylen
			sys.exit()

	
	else:
		k=i+1
		if ((p[i] != 'b') and (q[i] != 'b')): # if ith bit of p and q are known
			r= int((p1 + p[i]),2)
			s= int(q1 + q[i],2)
			R = ((2**k)*(int(N[:k],2) - 1)) + 2**(k-1)			# R = (2^i).(Ni -1) + 2^(i-1) as in Lemma 2
			
			if (abs(s - (R/r))<= 3): 
				Backtrack_factor_msb_pq_recursion(p1 + p[i],q1 + q[i],i+1)
		
		elif ((p[i] != 'b') and (q[i] == 'b')):		# if ith bit of p is unknown and q is known
			r=int((p1 + p[i]),2)
			s=int(q1 + '0',2)
			R = ((2**k)*(int(N[:k],2) - 1)) + 2**(k-1)			# R = (2^i).(Ni -1) + 2^(i-1) as in Lemma 2
			
			if (abs(s - (R/r))<= 3): 
				Backtrack_factor_msb_pq_recursion(p1 + p[i],q1 + '0',i+1)
			s= int(q1 + '1',2)
			R = ((2**k)*(int(N[:k],2) - 1)) + 2**(k-1)			# R = (2^i).(Ni -1) + 2^(i-1) as in Lemma 2
			
			if (abs(s - (R/r))<= 3):
				Backtrack_factor_msb_pq_recursion(p1 + p[i],q1 + '1',i+1)
		
		elif ((p[i] == 'b') and (q[i] != 'b')):		# if ith bit of q is unknown and p is known
			s=int(q1 + q[i],2)
			r= int(p1 + '0',2)
			R = ((2**k)*(int(N[:k],2) - 1)) + 2**(k-1)			# R = (2^i).(Ni -1) + 2^(i-1) as in Lemma 2
			
			if (abs(s - (R/r))<= 3):				
				Backtrack_factor_msb_pq_recursion(p1 + '0',q1 + q[i],i+1)
			r= int(p1 + '1',2)
			
			if (abs(s - (R/r))<= 3):
				Backtrack_factor_msb_pq_recursion(p1 + '1',q1 + q[i],i+1)
				
		elif ((p[i] == 'b') and (q[i] == 'b')):			# if ith bit of p and q are unknown
			r=  int(p1 + '0',2)
			s=  int(q1 + '0',2)
			R = ((2**k)*(int(N[:k],2) - 1)) + 2**(k-1)				# R = (2^i).(Ni -1) + 2^(i-1) as in Lemma 2
			
			if (abs(s - (R/r))<= 3):
				Backtrack_factor_msb_pq_recursion(p1 + '0',q1 + '0',i+1)
				
			r=  int(p1 + '1',2)
			s=  int(q1 + '0',2)
			
			if (abs(s - (R/r))<= 3):
				Backtrack_factor_msb_pq_recursion(p1 + '1',q1 + '0',i+1)
			
			r=  int(p1 + '0',2)
			s=  int(q1 + '1',2)
			
			if (abs(s - (R/r))<= 3):
				Backtrack_factor_msb_pq_recursion(p1 + '0',q1 + '1',i+1)
			
			r=  int(p1 + '1',2)
			s=  int(q1 + '1',2)
			
			if (abs(s - (R/r)) <= 3):
				Backtrack_factor_msb_pq_recursion(p1 + '1',q1 + '1',i+1)


def Backtrack_factor_msb_pqd_recursion(p1,q1,d1,i,flag):
	global start,keylen
	if (keylen > 1000000):
		print "panic width Execeed", ((time.time() - start),keylen)
		sys.exit()
	is_poss=[1,1,1,1,1,1,1,1]
	possible_values=possible_values_PQD
	if i==len(p):					# checking if factors are found
		keylen+=1
		if ((p1==binp) or (q1==binq)):
			print (time.time() - start) ,keylen
			sys.exit()
	else:
		j=0
		while j < len(is_poss):						# removing candidates using known bits
			if (p[i] != 'b'):
				if (str(possible_values[j][0]) != p[i]):
					is_poss[j]=0

			if (q[i] != 'b'):
				if (str(possible_values[j][1]) != q[i]):
					is_poss[j]=0
			
			if (d[i] != 'b'):
				if (str(possible_values[j][2]) != d[i]) :
					is_poss[j]=0
			j=j+1

		j=0
		if 1 in is_poss:					# applying constraints
			i=i+1
			R = ((2**i)*(int(N[:i],2) - 1)) + 2**(i-1)
			while j<len(is_poss):
				if is_poss[j] == 1:
					
					x=possible_values[j]
					r=int((p1 + x[0]),2)
					s=int((q1 + x[1]),2)
					if ((flag==0) and (i>3)):				# if p < q then pi < qi for all i and viceversa
						if s<r:
							is_poss[j]=0
					elif ((flag==1) and (i>3)):
						if s>r:
							is_poss[j]=0
					if (i>20):				# qi > 2^(i-1)
						if (s < (2**(i-1))):
							is_poss[j]=0

					if abs(s - (R/r))>=3: 			 #| qi -(R/pi) | <3
						is_poss[j]=0
				
					else:
						dk=int((d1+x[2]),2)
						left=Nr/(ee * 2**(m-i))
						right=((r+s)*k)/ mn2
						dz=left - right
						if (abs(dz-dk)>3):
							is_poss[j]=0
				j+=1

		j=0
		if 1 in is_poss:				 # check if valid candidate exist
			while j<len(is_poss):
				if is_poss[j] == 1:
					x=possible_values[j]
					Backtrack_factor_msb_pqd_recursion((p1 + x[0]),(q1 + x[1]),(d1 + x[2]), i,flag)

				j+=1

def Backtrack_factor_msb_all_recursion(p1,q1,d1,dp1,dq1,i,flag):
	global start,keylen
	if (keylen > 1000000):				# exit if panic width exceed
		print "panic width Execeed", ((time.time() - start),keylen)
		sys.exit()
	is_poss=[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]
	possible_values=possible_values_ALL
	if i==len(p):						# check if factors are found

		keylen+=1
		if ((p1==binp) or (q1==binq)):
			print (time.time() - start) ,keylen
			sys.exit()
	else:
		j=0
		while j < len(is_poss):						# removing candidates using known bits
			if (p[i] != 'b'):
				if (str(possible_values[j][0]) != p[i]):
					is_poss[j]=0

			if (q[i] != 'b'):
				if (str(possible_values[j][1]) != q[i]):
					is_poss[j]=0
			
			if (d[i] != 'b'):
				if (str(possible_values[j][2]) != d[i]) :
					is_poss[j]=0
					
			if (dp[i] != 'b'):
				if (str(possible_values[j][3]) != dp[i]) :
					is_poss[j]=0

			if (dq[i] != 'b'):
				if (str(possible_values[j][4]) != dq[i]) :
					is_poss[j]=0
			
			j=j+1
			
			
		j=0
		if 1 in is_poss:
			i=i+1
			R = ((2**i)*(int(N[:i],2) - 1)) + 2**(i-1)
			while j<len(is_poss):			# applying constraints
				if is_poss[j] == 1:
					x=possible_values[j]
					r=int((p1 + x[0]),2)
					s=int((q1 + x[1]),2)
					
					if ((flag==0) and (i>3)):				# if p < q then pi < qi for all i and viceversa
						if s<r:
							is_poss[j]=0
					elif ((flag==1) and (i>3)):
						if s>r:
							is_poss[j]=0
					
					if (i>20):						# qi < 2^(i-1)
						if (s < (2**(i-1))):
							is_poss[j]=0
					if abs(s - (R/r))>=3:		# | qi - (R/pi)| < 3
						is_poss[j]=0
					
					else:
						dk=int((d1+x[2]),2)
						left=Nr/(ee * 2**(m-i))
						right=((r+s)*k)/ mn2
						dz=left - right
						if (abs(dz-dk)>=2):
							is_poss[j]=0
						else:
							dpk=int(dp1+x[3],2)
							dpz= (r*kp)/ee					#dpi
							if abs(dpk-dpz)>=2:				# |dpi - dpi'| < 2
								is_poss[j]=0
				
				
							else:
								dqk=int(dq1+x[4],2)
								dqz= (s*kq)/ee
								if abs(dqk-dqz)>=2: # |dqi - dqi'| < 2
									is_poss[j]=0
				j+=1
				
		j=0
		if 1 in is_poss:				#check if any valid candidate is there
			while j<len(is_poss):
				if is_poss[j] == 1:
					x=possible_values[j]
					Backtrack_factor_msb_all_recursion((p1 + x[0]),(q1 + x[1]),(d1 + x[2]),(dp1 + x[3]),(dq1 + x[4]), i,flag)
				j+=1


if option == 1:
	Backtrack_factor_msb_pq_recursion(p[0],q[0],1)		
elif option == 2:
	Backtrack_factor_msb_pqd_recursion(p[0],q[0],d[0],1,1)		# start process for p < q
	Backtrack_factor_msb_pqd_recursion(p[0],q[0],d[0],1,0)		# start process for p > q
elif option == 3:
	Backtrack_factor_msb_all_recursion(p[0],q[0],d[0],dp[0],dq[0],1,1)		# start process for p < q 
	Backtrack_factor_msb_all_recursion(p[0],q[0],d[0],dp[0],dq[0],1,0)		# start process for p > q













