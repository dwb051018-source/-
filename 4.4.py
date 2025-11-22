# ---------- 扩展欧几里得算法 ----------
# 用来求解： ax + by = gcd(a, b)
# 返回 (x, y, gcd)，其中：
#   x、y 是系数，使得 ax + by = gcd(a, b)
#   gcd 是最大公约数
def ext_gcd(a, b):
    if b == 0:
        return 1, 0, a     # 当 b=0 时，gcd(a,0)=a，此时 x=1、y=0
    else:
        # 递归调用，直到 b 变为 0
        x, y, gcd = ext_gcd(b, a % b)
        # 回溯时计算新的系数
        x, y = y, (x - (a // b) * y)
        return x, y, gcd

# ---------- 将十六进制字符串转换为 UTF-8 文本 ----------
def hex_to_char(hex_str):
    return bytes.fromhex(hex_str).decode('utf-8')

# ---------- 读取 Frame0 ----------
with open("Frame0") as file:
    message = file.read()
    n_1 = int(message[:256], 16)        # 读取 n
    e_1 = int(message[256:512], 16)     # 读取 e1
    c_1 = int(message[512:], 16)        # 读取密文 c1
file.close()

# ---------- 读取 Frame4 ----------
with open("Frame4") as file:
    message = file.read()
    n_2 = int(message[:256], 16)        # 读取 n
    e_2 = int(message[256:512], 16)     # 读取 e2
    c_2 = int(message[512:], 16)        # 读取密文 c2
file.close()

# ---------- 使用扩展欧几里得算法求解 x, y ----------
# 满足 e1 * x + e2 * y = gcd(e1, e2)
# 在共模攻击中，要求 gcd(e1,e2)=1（两个指数互素）
x, y, g = ext_gcd(e_1, e_2)

# ---------- 恢复明文 ----------
# 根据公式：
#   m = (c1^x * c2^y) mod n
#
# 说明：
#   若 x 为负，需要使用：c^{-x} = (c^{-1})^x
#   Python 的 pow(c, x, n) 可直接处理负指数（自动求逆元）
plaintext = pow(c_1, x, n_1) * pow(c_2, y, n_2)
plaintext = plaintext % n_1

# ---------- 输出十六进制明文 ----------
print(hex(plaintext))

# ---------- 输出最后 8 字节的 ASCII 文本 ----------
print(hex_to_char(hex(plaintext)[-16:]))
