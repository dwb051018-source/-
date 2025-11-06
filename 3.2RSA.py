import secrets
import time

# ---------------------------
# 扩展欧几里得算法
# ---------------------------
def egcd(a: int, b: int):
    if b == 0:
        return (a, 1, 0)
    else:
        g, x1, y1 = egcd(b, a % b)
        x = y1
        y = x1 - (a // b) * y1
        return (g, x, y)

# ---------------------------
# 求 a 在 mod m 下的逆元
# ---------------------------
def invmod(a: int, m: int) -> int:
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError(f"invmod 失败: gcd({a},{m})={g}")
    return x % m

# ---------------------------
# Miller-Rabin 素性检测
# ---------------------------
def is_probable_prime(n: int, k: int = 8) -> bool:
    if n < 2:
        return False
    for p in [2,3,5,7,11,13,17,19,23,29,31,37,41,43,47]:
        if n % p == 0:
            return n == p
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x == 1 or x == n-1:
            continue
        for _ in range(s-1):
            x = pow(x, 2, n)
            if x == n-1:
                break
        else:
            return False
    return True

# ---------------------------
# 生成随机素数
# ---------------------------
def generate_prime(bits: int) -> int:
    while True:
        p = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if is_probable_prime(p):
            return p

# ---------------------------
# 自动生成 p,q，使得 gcd(e, (p-1)*(q-1))==1
# ---------------------------
def generate_keypair(bits: int = 256, e: int = 3, max_attempts: int = 2000):
    attempts = 0
    while attempts < max_attempts:
        attempts += 1
        p = generate_prime(bits)
        q = generate_prime(bits)
        if p == q:
            continue
        et = (p-1)*(q-1)
        if egcd(e, et)[0] == 1:
            n = p * q
            d = invmod(e, et)
            pub = (e, n)
            priv = (d, n)
            return pub, priv, p, q
    raise RuntimeError("超过最大尝试次数，未能生成互素 p,q")

# ---------------------------
# 加密/解密整数
# ---------------------------
def encrypt_int(m: int, pubkey):
    e, n = pubkey
    if m >= n:
        raise ValueError("明文整数必须小于 n")
    return pow(m, e, n)

def decrypt_int(c: int, privkey):
    d, n = privkey
    return pow(c, d, n)

# ---------------------------
# 字符串与整数互转
# ---------------------------
def str_to_int(s: str) -> int:
    return int.from_bytes(s.encode('utf-8'), 'big')

def int_to_str(i: int) -> str:
    length = (i.bit_length() + 7) // 8
    return i.to_bytes(length, 'big').decode('utf-8')

# ---------------------------
# 小素数示例
# ---------------------------
def demo_small_primes():
    p = 47
    q = 59
    e = 3
    pub, priv = generate_keys_from_primes_safe(p, q, e)
    print("public:", pub)
    print("private:", priv)
    m = 42
    c = encrypt_int(m, pub)
    m2 = decrypt_int(c, priv)
    print("m:", m, "-> c:", c, "-> m2:", m2)

# ---------------------------
# 安全生成小素数的函数
# ---------------------------
def generate_keys_from_primes_safe(p, q, e):
    et = (p-1)*(q-1)
    if egcd(e, et)[0] != 1:
        raise ValueError("e 与 et 不互素，请换一个 p,q")
    d = invmod(e, et)
    n = p * q
    return (e, n), (d, n)

# ---------------------------
# 大素数示例（自动循环直到成功）
# ---------------------------
def demo_large_primes_auto(bits=256, e=3):
    print(f"开始生成 {bits}-bit 素数对，e={e}")
    pub, priv, p, q = generate_keypair(bits, e)
    print("n 比特长度:", pub[1].bit_length())
    s = "Hello RSA"
    m = str_to_int(s)
    if m >= pub[1]:
        raise ValueError("字符串整数 >= n，请分块加密或生成更大素数")
    c = encrypt_int(m, pub)
    m2 = decrypt_int(c, priv)
    s2 = int_to_str(m2)
    print("原文:", s, "解密后:", s2)

# ---------------------------
# 主执行
# ---------------------------
if __name__ == "__main__":
    print("=== 小素数示例 ===")
    demo_small_primes()
    print("\n=== 较大素数示例 ===")
    demo_large_primes_auto(bits=256, e=3)
