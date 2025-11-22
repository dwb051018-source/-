import gmpy2

# ---------- 求最大公约数（用于判断两个 n 是否共享质因子） ----------
def gcd(a, b):
    if b == 0:
        return a
    else:
        return gcd(b, a % b)

# ---------- 将十六进制字符串转换为 UTF-8 ----------
def hex_to_char(hex_str):
    return bytes.fromhex(hex_str).decode('utf-8')

# ---------- 读取 Frame1 ----------
with open("Frame1") as file:
    message = file.read()
    n_1 = int(message[:256], 16)          # RSA 模数 n1
    e_1 = int(message[256:512], 16)       # 公钥 e1
    c_1 = int(message[512:], 16)          # 密文 c1
file.close()

# ---------- 读取 Frame18 ----------
with open("Frame18") as file:
    message = file.read()
    n_2 = int(message[:256], 16)          # RSA 模数 n2
    e_2 = int(message[256:512], 16)       # 公钥 e2
    c_2 = int(message[512:], 16)          # 密文 c2
file.close()

# ---------- 利用 gcd(n1, n2) 找到共同质因子 p ----------
# 若 n1 和 n2 共用一个质因子 p：
#     n1 = p * q1
#     n2 = p * q2
p = gcd(n_1, n_2)

# ---------- 计算 q1 并获取 phi(n1) ----------
q_1 = n_1 // p
phi_1 = (p - 1) * (q_1 - 1)               # φ(n) = (p−1)(q−1)

# ---------- 计算 d1 并解密 c1 ----------
d_1 = gmpy2.invert(e_1, phi_1)            # d1 = e1^{-1} mod φ(n1)
c_1 = pow(c_1, d_1, n_1)                  # 明文 = c1^d1 mod n1
ciphertext_1 = hex(c_1)
print(ciphertext_1)
print(hex_to_char(ciphertext_1[-16:]))     # 输出最后 8 字节 ASCII

# ---------- 同样的方式解密第二份密文 ----------
q_2 = n_2 // p
phi_2 = (p - 1) * (q_2 - 1)
d_2 = gmpy2.invert(e_2, phi_2)
c_2 = pow(c_2, d_2, n_2)
ciphertext_2 = hex(c_2)
print(ciphertext_2)
print(hex_to_char(ciphertext_2[-16:]))     # 输出明文
