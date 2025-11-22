import gmpy2  # 导入 gmpy2 库，用于高精度整数计算和数论函数

# ---------- 定义一个函数，用费马分解法因式分解 n ----------
def factor(n):
    # 从 n 的平方根开始尝试
    a = gmpy2.iroot(n, 2)[0]  # 取 n 的整数平方根
    while True:
        a += 1  # 每次尝试下一个整数
        b2 = a*a - n  # 计算 b^2 = a^2 - n
        if gmpy2.is_square(b2):  # 如果 b^2 是完全平方数
            b2 = gmpy2.mpz(b2)  # 转成 gmpy2 的大整数类型
        b, xflag = gmpy2.iroot(b2, 2)  # 取 b 的整数平方根，xflag 表示是否精确平方根
        assert xflag  # 确认 b2 是完全平方数
        return (a-b, a+b)  # 返回 n 的两个因子 p 和 q

# ---------- 定义一个函数，将十六进制字符串转为字符 ----------
def hex_to_char(hex_str):
    return bytes.fromhex(hex_str).decode('utf-8')

# ---------- 读取加密文件 ----------
with open("Frame10") as file:
    message = file.read()  # 读取整个文件内容
    n = int(message[:256], 16)  # 前 256 个字符是 n（十六进制转整数）
    e = int(message[256:512], 16)  # 接下来的 256 个字符是 e
    c = int(message[512:], 16)  # 剩下的是密文 c
file.close()

# ---------- 分解 n 得到 p 和 q ----------
p, q = factor(n)
print("p=", hex(p))  # 输出 p 的十六进制形式
print("q=", hex(q))  # 输出 q 的十六进制形式

# ---------- 计算私钥 d ----------
fai = (p-1)*(q-1)  # 欧拉函数 φ(n) = (p-1)*(q-1)
d = gmpy2.invert(e, fai)  # 计算 e 关于 φ(n) 的模反元素，即私钥 d
print("d=", hex(d))

# ---------- 使用私钥解密密文 ----------
m = gmpy2.powmod(c, d, n)  # m = c^d mod n
print("m=", hex(m))  # 输出解密结果的十六进制形式

# ---------- 取最后 16 个十六进制字符作为明文 ----------
plaintext = hex(m)[-16:]
print(hex_to_char(plaintext))  # 将十六进制明文转换为字符并打印
