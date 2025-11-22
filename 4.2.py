import gmpy2  # 导入 gmpy2 库，用于大整数运算和数论函数

# ---------- 定义 Pollard 因式分解法函数 ----------
def pollard(N):
    a = 2  # 初始化 a
    B = 2  # 初始化迭代次数 B
    while True:
        a = gmpy2.powmod(a, B, N)  # 计算 a^B mod N
        res = gmpy2.gcd(a-1, N)  # 计算 gcd(a-1, N)
        # 如果找到非平凡因子，则返回
        if res != 1 and res != N:
            q = N // res  # N 除以 res 得到另一个因子
            return res, q
        B += 1  # 否则增加 B，继续循环

# ---------- 定义一个函数，将十六进制字符串转为字符 ----------
def hex_to_char(hex_str):
    return bytes.fromhex(hex_str).decode('utf-8')

# ---------- 读取加密文件 ----------
with open("Frame19") as file:
    message = file.read()  # 读取整个文件内容
    n = int(message[:256], 16)  # 前 256 个字符是 n（十六进制转整数）
    e = int(message[256:512], 16)  # 接下来的 256 个字符是 e
    c = int(message[512:], 16)  # 剩下的是密文 c
file.close()

# ---------- 使用 Pollard 方法分解 n 得到 p 和 q ----------
p, q = pollard(n)
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
