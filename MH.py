from math import gcd
from random import randint
import sys
import bitstring
import base64

def vec_num(vec, n):
    for i in range(len(vec)):
        vec[i] *= n
    return(vec)

def add_vecs (vec1, vec2):
    for i in range(len(vec1)):
        vec1[i] += vec2[i]
        vec1[i] = round(vec1[i], 4)
    return(vec1)

def minus_vecs (vec1, vec2):
    for i in range(len(vec1)):
        vec1[i] -= vec2[i]
        vec1[i] = round(vec1[i], 4)
    return(vec1)


def simple_num(S):
    count = randint(3, S)
    while gcd(S,count) != 1:
        count += 1
    return count

def inverse(a, S):
    t = 0
    r = S
    newt = 1
    newr = a
    while newr != 0:
        quo = r // newr
        t, newt = newt, t - quo * newt
        r, newr = newr, r - quo * newr
    if r > 1:
        print('Error 1')
        return
    if t < 0:
        t += S
    return t


def generate_numbers(n, b, u):
    if len(u) > 0:
        left = 0
        for i in u:
            left += i
        right = 2 ** (b-n+len(u))
    else:
        left = 1
        right = 2 ** (b-n)
    u.append(randint(left, right))
    if len(u) < n:
        return generate_numbers(n, b, u)
    else:
        return u

def public_key(a_inv, u, S):
    w = []
    for i in range(len(u)):
        w_i = (a_inv * u[i]) // S
        w.append(w_i)
    return w


def volume(u: list, b):
    sum_u = 0
    for i in u:
        sum_u += i
    s = randint(sum_u, 2 ** b)
    return s

def in_file_pkey(w):
    str_w = ''
    for i in w:
        str_w += (str(i) +',')
    file = open('public_key','w')
    file.write(str_w[:-1])
    file.close()
    return

def in_file_skey(u, a, s):
    str_u = ''
    for i in u:
        str_u += (str(i) +',')
    file = open('private_key','w')
    file.write(str_u[:-1] + '\n')
    file.write(str(a) + '\n')
    file.write(str(s) + '\n')
    file.close()
    return

def in_file_enc(c):
    file = open('encryption_text','wb')
    c_bytes = str(c).encode()
    file.write(base64.b32encode(c_bytes))
    file.close()
    return

def genkeys(n, b):
    u = []
    u = generate_numbers(int(n), int(b), u)
    S = volume(u, int(b))
    a = simple_num(S)
    a_inv = inverse(a, S)
    w = public_key(a_inv, u, S)
    in_file_pkey(w)
    in_file_skey(u, a, S)
    return


def enc(M, w):
    m_byte = M.encode()
    m_bit = bitstring.BitArray(m_byte)[2:]
    if len(m_bit) > len(w):
        print('The first n bits were encoded')
    if len(m_bit) < len(w):
        print('The message was too short')
        return
    c = 0
    for i in range(len(w)):
        c += m_bit[i]*int(w[i])
    in_file_enc(c)
    return


def mu(bi,bjk):
    sp_up = 0
    sp_down = 0
    for i in range(len(bi)):
        sp_up += bi[i]*bjk[i]
        sp_down += bjk[i]**2
    mu_ij = sp_up/sp_down
    return round(mu_ij, 4)


def norma_2(vec):
    sp = 0
    for i in range(len(vec)):
        sp += (vec[i]**2)    
    return round(sp, 4)


def GramSchmidt(b):
    b_ort = list()
    for i in range(0,len(b)):
        s = [0]*len(b[0])
        if i != 0:
            for j in range(0,i):
                my_ij = mu(b[i],b_ort[j])
                tmp = b_ort[j].copy()
                s = add_vecs(s, vec_num(tmp, my_ij))  
            cur = minus_vecs(b[i], s)
        else:
            cur = b[i]
        b_ort.append(cur)
    return b_ort

def LLL(b, n):
    b_ort = GramSchmidt(b)
    delta = 3/4
    i=1
    # Было i = 2
    while i < n:
        for j in range(i-1,-1,-1):
            if abs(mu(b[i],b_ort[j])) > 0.5:
                #drob = mu(b[i],b[j]) - int(mu(b[i],b[j]))
                tmp_bj = b[j].copy()
                b[i] = minus_vecs(b[i], vec_num(tmp_bj, round(mu(b[i],b_ort[j]))))
                b_ort = GramSchmidt(b)
        if (delta - (mu(b[i],b_ort[i-1]))**2) * norma_2(b_ort[i-1]) <= norma_2(b_ort[i]):
            i += 1
        else:
            b[i], b[i-1] = b[i-1], b[i]
            i = max(i-1,1)
    return b

def check(b,w,c):
    for i in b:
        flag = True
        for j in range(len(i)):
            if i[j] != 0 or i[j] != 0:
                flag = False
                break
        if flag and i[len(i)-1] == 0:
            return (0, i)
    sum_w = 0
    for i in w:
        sum_w += int(i)
    c = sum_w - int(c)
    return (1, c)


def basisCreation(w,c):
    b = list()
    tmp = list()
    for i in range(0,len(w)+1):
        tmp.append(0)
    for i in range(0,len(w)):
        tmp2 = tmp.copy()
        tmp2[i] = 1
        tmp2[len(w)] = -1 * int(w[i])
        b.append(tmp2)
    tmp[len(w)] = int(c)
    b.append(tmp)
    return b


def in_file_dec(vec):
    str_01 = '0b'
    for i in vec:
        str_01 += str(i)
    str_bit = bitstring.BitArray(str_01)
    dec_txt = str_bit.hex.decode('utf-8')
    file = open('decryption_text','w')
    file.write(dec_txt)
    file.close()
    return

def dec(w, c):
    b = basisCreation(w, c)
    b_new = LLL(b, len(w)+1)
    flag, vec = check(b_new, w, int(c))
    if flag == 0:
        in_file_dec(vec)
        return
    else:
        b = basisCreation(w, vec)
        b_new = LLL(b, len(w)+1)
        flag, vec = check(b_new, w, c)
        if flag == 0:
            in_file_dec(vec)
            return
        else:
            print('Unable to decode')
            return


def out_file_pkey(f):
    file = open(f, 'r')
    str_w = file.read()
    w = str_w.split(',')
    file.close()
    return w

def out_file_text(f):
    file = open(f, "r", encoding="utf-8")
    txt = file.read()
    file.close()
    return txt


def out_file_ciphertext(f):
    file = open(f, 'rb')
    txt_bytes = file.read()
    txt = base64.b32decode(txt_bytes)

    file.close()
    return txt

flag = True
if len(sys.argv) > 1: 
    mode = sys.argv[1]
else:
    mode = input("Select the operating mode: gen, enc, dec ")

while (flag == True):
    if __name__ == "__main__":
        if mode == "gen":
            print("genkeys")
            flag = False
            if len(sys.argv) > 3:
                n = sys.argv[2] 
                b = sys.argv[3]
            else:
                n = input("Input n")
                b = input("Input b")
            genkeys(n,b)
        elif mode == "enc":
            print("encryption")
            flag = False
            if len(sys.argv) > 3:
                ptf = sys.argv[2] 
                ptf_txt = sys.argv[3]
            else:
                ptf = input("Input path to file with public key")
                ptf_txt = input("Input path to file with text")
            w = out_file_pkey(ptf)
            text = out_file_text(ptf_txt)
            enc(text, w)    
        elif mode == "dec":
            print("decryprion")
            flag = False
            if len(sys.argv) > 3:
                ptf = sys.argv[2] 
                ptf_ctext = sys.argv[3]
            else:
                ptf = input("Input path to file public key")
                ptf_ctext = input("Input path to file with cipher text")
            w = out_file_pkey(ptf)
            c = out_file_ciphertext(ptf_ctext)
            dec(w,c)    
        else:
            mode = input("unknown command, repeat input ")

