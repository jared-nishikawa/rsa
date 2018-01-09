#!/usr/bin/python

import random

NUMTESTS = 20
BLKSIZE = 256

class DivByZero(Exception):
        pass

# Division algorithm
# Return q and r such that
# n = dq + r, 0 <= r < d
# Currently does not work for negative numbers
def div(n,d):
    assert (n,d) == (int(n), int(d))
    assert d != 0
    assert n > 0 and d > 0
    
    q = 1
    while d * q <= n:
            q += 1
    q -= 1
    r = n - d * q
    return q,r

# Returns GCD of n and d
def euc(n,d):
    if n % d == 0:
            return d
    q,r = div(n,d)
    return euc(d,r)

def push(L,a):
        L_ = [L[1],a]
        return L_

# Suppose gcd(a,b) = d
# Then there exists x,y such that
# ax + by = d
# This function returns x,y
def eea(a,b):
    R = [a,b]
    S = [1,0]
    T = [0,1]

    while 1:
        q = R[0] / R[1]
        r = R[0] - q * R[1]
        s = S[0] - q * S[1]
        t = T[0] - q * T[1]
        R = push(R,r)
        S = push(S,s)
        T = push(T,t)
        if r == 0:
            break

    # Interestingly, all I really care about is S[-2] and T[-2]
    return S[0], T[0]

# Find multiplicative inverse of a mod n
# Assuming a and n are relatively prime
def inv(a,n):
    # So, we know ax + ny = 1
    x,y = eea(a,n)
    # The inverse we seek is x
    return x % n
        

# s_(i+1) = s_(i-1) - q * s_i
# t_(i+1) = t_(i-1) - q * t_i

# Example: n = 700, d = 43
# 700 = 43 * 16 + 12
# 43 = 12 * 3 + 7
# 12 = 7 * 1 + 5
# 7 = 5 * 1 + 2
# 5 = 2 * 2 + 1
# 2 = 2 * 1 + 0

#       q       r       s       t
#               700     1       0
#               43      0       1
#       16      12      1       -16
#       3       7       -3      49
#       1       5       4       -65
#       1       2       -7      114
#       2       1       18      -293
#       1       0       -25     407
#                       43      700

# This is pretty slow still..
# NUMTESTS = 20
def fermat(n):
    i = 0
    while i < NUMTESTS:
        a = random.randint(2,n-2)
        check = pow(a,n-1,n)
        if check != 1:
                return 0
        i += 1
    return 1

def miller_rabin(n,a):
    d = n-1
    s = 0
    while d % 2 == 0:
        d /= 2
        s += 1
    check1 = pow(a,d,n)
    if check1 == 1:
        return 1
    for r in range(s):      
        check2 = pow(a, d* 2**r, n)
        if check2 == n-1:
            return 1
    return 0



def pseud(n):
    F = miller_rabin(n,2)
    #F = fermat(n)
    while F != 1:
        n += 1
        F = miller_rabin(n,2)
        #F = fermat(n)
    return n

def bit_gen(bits):
    ret = '1'
    for i in xrange(bits-1):
        t = random.randint(0,1)
        ret += str(t)
    return int( ret, 2)


# IF p and q are 1024 bit primes, then N is 2048 bits
def prime_gen(bits):
    a = pseud( bit_gen( bits ) )
    return a

def rsa(bits):
    p = pseud( bit_gen( bits ) )
    q = pseud( bit_gen( bits ) )
    N = p * q
    phi = (p-1) * (q-1)
    e = 65537
    d = inv(e, phi)
    return p,q,N,e,d

def colon_hex(a):
    x = hex(a)[2:].rstrip('L')
    while len(x) % 2 != 0:
        x = '0' + x
    pairs = [ x[2 * i] + x[2 * i+1] for i in range( len(x) / 2)]
    temp = ':'.join(pairs)
    return split_lines(temp, 45)

def split_lines(s, width):
    lines = []
    for i in range( len(s) / width):
        lines.append( s[width * i: width * (i+1) ])
    if len(s) % width != 0:
        lines.append( s[width * (i+1):])
    pad = ' '*4
    return pad + '\n    '.join(lines)

def show( K ):
    assert len(K) == 5
    print "Prime 1:\n", colon_hex( K[0] )
    print "Prime 2:\n", colon_hex( K[1] )
    print "Modulus:\n", colon_hex( K[2] )
    print "Public exponent:", K[3], '(' + hex( K[3] ) + ')'
    print "Private exponent\n", colon_hex( K[4] )

def ntox(n):
    assert n == int(n)
    ret = ''
    while n > 0:
        ret += chr( n % 256 )
        n /= 256
    return ret

def xton(x):
    acc = 0
    for index,byte in enumerate(x):
        value = ord(byte) * (256 ** index)
        acc += value
    return acc


# blksize in bytes
# each byte is 8 bits
# for example, 1024 bits = 128 bytes
def encrypt_block(msg, e, N, blksize):
    assert len(msg) == blksize
    # Almost forgot to reduce modulo N...
    msg_val = xton(msg) % N
    cip_val = pow(msg_val, e, N)
    temp = ntox(cip_val)
    while len(temp) < blksize:
        temp += '\x00'
    return temp
                

def decrypt_block(cip, d, N, blksize):
    assert len(cip) == blksize
    # Almost forgot to reduce modulo N...
    cip_val = xton(cip) % N
    msg_val = pow(cip_val, d, N)
    temp = ntox(msg_val)
    while len(temp) < blksize:
        temp += '\x00'
    return ntox(msg_val)
        
def encrypt(msg, K):
    e = K[3]
    N = K[2]
    blksize = BLKSIZE
    cipher = ''
    
    # padding
    while len(msg) % 256 != 0:
        msg += '\x00'
    
    for i in xrange( len(msg) / 256):
        chunk = msg[256*i: 256*(i+1)]
        cipher_chunk = encrypt_block(chunk, e, N, blksize)
        cipher += cipher_chunk
    return cipher

def decrypt(cip, K):
    d = K[4]
    N = K[2]
    blksize = BLKSIZE
    plain = ''

    # check padding
    assert len(cip) % 256 == 0
    for i in xrange( len(cip) / 256):
        chunk = cip[256*i: 256*(i+1)]
        plain_chunk = decrypt_block(chunk, d, N, blksize)
        plain += plain_chunk
    return plain
