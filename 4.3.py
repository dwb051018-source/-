import gmpy2  # 用于高精度计算和数论函数

# ---------- 求最大公约数 ----------
def gcd(a, b):
    if b == 0:
        return a
    else:
        return gcd(b, a % b)

# ---------- 根据 CRT 公式计算 Mi = m / mi ----------
def Get_Mi(m_list, m):
    M_list = []
    for mi in m_list:
        M_list.append(m // mi)
    return M_list

# ---------- 计算每个 Mi 关于 mi 的逆元 ----------
def Get_resMi(M_list, m_list):
    resM_list = []
    for i in range(len(M_list)):
        # 使用扩展欧几里得算法求逆元，保证正值
        resM_list.append((Get_ni(M_list[i], m_list[i])[0] + m_list[i]) % m_list[i])
    return resM_list

# ---------- 扩展欧几里得算法求解 ax + by = gcd(a,b) ----------
def Get_ni(a, b):
    if b == 0:
        x = 1
        y = 0
        q = a  # gcd(a,0) = a
        return x, y, q
    ret = Get_ni(b, a % b)
    x = ret[0]
    y = ret[1]
    q = ret[2]
    temp = x
    x = y
    y = temp - a // b * y
    return x, y, q

# ---------- 使用中国剩余定理计算最终结果 ----------
def result(a_list, m_list):
    # 检查模数是否两两互素
    for i in range(len(m_list)):
        for j in range(i + 1, len(m_list)):
            if 1 != gcd(m_list[i], m_list[j]):
                print("不能直接使用中国剩余定理")
                return
    # 计算总模数 m = m1*m2*...
    m = 1
    for mi in m_list:
        m *= mi
    # 计算每个 Mi = m / mi
    Mi_list = Get_Mi(m_list, m)
    # 计算每个 Mi 的逆元
    Mi_inverse = Get_resMi(Mi_list, m_list)
    x = 0
    xi_list = []
    # 计算 CRT 组合 x = Σ ai * Mi * Mi_inverse (mod m)
    for i in range(len(a_list)):
        xi = a_list[i] * Mi_list[i] * Mi_inverse[i]
        xi_list.append(xi)
        x += xi
        x %= m
    # 对 CRT 结果取 5 次方根（Håstad 攻击）
    a, b = gmpy2.iroot(x, 5)  # b 为布尔值，表示是否精确根
    if b == 1:
        x = a
    return x

# ---------- 十六进制转字符 ----------
def hex_to_char(hex_str):
    return bytes.fromhex(hex_str).decode('utf-8')

# ---------- 读取五个加密文件 ----------
n = 0
a_list = []  # 存放密文 c
m_list = []  # 存放模数 n
for filename in ["frame3", "frame8", "frame12", "frame16", "frame20"]:
    with open(filename) as file:
        message = file.read()
        n = int(message[:256], 16)  # 前 256 位是 n
        e = int(message[256:512], 16)  # 接下来的 256 位是 e（5）
        c = int(message[512:], 16)  # 剩下是密文 c
        a_list.append(c)
        m_list.append(n)
    file.close()

# ---------- 解密并输出明文 ----------
plaintext = hex(result(a_list, m_list))
print(hex_to_char(plaintext[-16:]))  # 取最后 16 个十六进制字符并转为字符串
