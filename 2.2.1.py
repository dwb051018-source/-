from Crypto.Cipher import AES
import base64
import binascii
from hashlib import sha1

def jiou(ka_hex: str) -> str:
    """
    将 16 进制字符串表示的 8 字节（16 hex chars）转换为带奇偶校验位的 8 字节 hex（即每 7-bit 加一位奇偶校验 -> 8-bit）。
    返回值为没有 '0x' 前缀、固定长度的 hex 字符串（小写）。
    说明：输入 ka_hex 可以是 'ea8645d97ff725a8' 这样的 16-char hex。
    """
    # 规范化：小写且去掉可能的 0x
    ka_hex = ka_hex.lower().strip()
    if ka_hex.startswith('0x'):
        ka_hex = ka_hex[2:]
    # 需要按长度补齐二进制位数：每个 hex 是 4 位
    bitlen = len(ka_hex) * 4
    a = bin(int(ka_hex, 16))[2:].zfill(bitlen)  # 补齐前导零，确保长度为 bitlen

    out_bits = []
    # 按每 8 位跳跃，但实际每块我们取前 7 位，再加校验位：
    # 例如 a[0:7], a[8:15], ... 等（原实现跳步 8，取 7）
    # 我们用 i 从 0 到 bitlen-1 步进 8
    for i in range(0, bitlen, 8):
        seven = a[i:i+7]
        # 如果最后一组不足 7 位，先用 0 填充（一般不会发生，因为 bitlen 为 8 的倍数）
        if len(seven) < 7:
            seven = seven.ljust(7, '0')
        # 计算奇偶校验（1 表示奇数个 1，则校验位应是 0；你原来逻辑是如果 1 的个数为偶数就 append '1'）
        ones = seven.count('1')
        parity_bit = '1' if (ones % 2 == 0) else '0'   # 保持你原来的策略（偶数个 1 -> parity 1）
        out_bits.append(seven + parity_bit)

    out_bin = ''.join(out_bits)
    # 转回 hex，注意补齐：总位数应为 len(out_bin)（应是 8 * (bitlen/8) = bitlen）
    # 但每段从 7->8，所以总位数 = bitlen + (bitlen/8) （如果原来是 64 位 => 输出 72 位？）
    # 实际上我们输入通常是 64 位（16 hex -> 64 bits），分 8 段，每段输出 8 位，所以总仍为 64 位
    # 因为我们步长为 8 并取 7，然后补 1，8 段 -> 8*8 = 64 bits，长度相同。
    hex_len = len(out_bin) // 4
    val = int(out_bin, 2)
    fmt = '{:0' + str(hex_len) + 'x}'
    return fmt.format(val)

def pkcs7_unpad(data: bytes) -> bytes:
    if not data:
        raise ValueError("Empty data")
    pad = data[-1]
    if pad == 0 or pad > len(data):
        raise ValueError("Invalid padding")
    if data[-pad:] != bytes([pad]) * pad:
        raise ValueError("Invalid padding")
    return data[:-pad]

# ---------- 主流程 ----------
cipher_b64 = '9MgYwmuPrjiecPMx61O6zIuy3MtIXQQ0E59T3xB6u0Gyf1gYs2i3K9Jxaa0zj4gTMazJuApwd6+jdyeI5iGHvhQyDHGVlAuYTgJrbFDrfB22Fpil2NfNnWFBTXyf7SDI'
ciphertext = base64.b64decode(cipher_b64)

v = '12345678<8<<<1110182<1111167<<<<<<<<<<<<<<<4'
no = v[:10]
birth = v[13:20]
date = v[21:28]
mrz_information = no + birth + date  # 这里与你原来一致

# SHA-1 处理
h_mrz = sha1(mrz_information.encode()).hexdigest()
kseed = h_mrz[:32]  # 前 16 bytes (32 hex chars)
c = '00000001'
d = kseed + c
h_D = sha1(binascii.unhexlify(d)).hexdigest()
# h_D 是 40 hex chars (20 bytes)
ka = h_D[:16]   # 8 bytes (16 hex chars)
kb = h_D[16:32] # 下一个 8 bytes

k1 = jiou(ka)
k2 = jiou(kb)
key_hex = k1 + k2  # 合并成 32 hex chars -> 16 字节 => AES-128 key

# 检查 key_hex 长度是否正确
if len(key_hex) != 32:
    raise ValueError("派生的 key_hex 长度不是 32，实际为: {}".format(len(key_hex)))

key_bytes = binascii.unhexlify(key_hex)
iv = binascii.unhexlify('0' * 32)  # 16 字节 IV (全 0)

cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
pt_padded = cipher.decrypt(ciphertext)

# 尝试去填充并打印可读字符串（若不是可打印则以 hex 打印）
try:
    pt = pkcs7_unpad(pt_padded)
    try:
        print("Decrypted (utf-8):")
        print(pt.decode('utf-8', errors='replace'))
    except Exception:
        print("Decrypted (bytes):", pt)
except ValueError as e:
    # 去填充失败，仍打印原始解密结果的 hex / 尝试 decode
    print("Unpad failed:", e)
    print("Decrypted raw (hex):", binascii.hexlify(pt_padded))
    print("Decrypted raw (as bytes):", pt_padded)
