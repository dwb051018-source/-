import base64

# =========================
# 第1题：十六进制 → Base64
# =========================
def hex_to_base64(hex_str):
    raw_bytes = bytes.fromhex(hex_str)
    return base64.b64encode(raw_bytes).decode('utf-8')


# =========================
# 第2题：固定异或
# =========================
def fixed_xor(hex_str1, hex_str2):
    b1 = bytes.fromhex(hex_str1)
    b2 = bytes.fromhex(hex_str2)
    if len(b1) != len(b2):
        raise ValueError("输入的两个十六进制字符串长度必须一致！")
    return bytes([x ^ y for x, y in zip(b1, b2)]).hex()


# =========================
# 第3题：单字节异或破解
# =========================
def single_byte_xor(cipher_bytes, key):
    return bytes([b ^ key for b in cipher_bytes])

def score_text(text):
    """简单英文打分函数"""
    freq_chars = b'ETAOIN SHRDLUetaoinshrdlu '
    return sum([chr(b) in freq_chars.decode() for b in text])

def break_single_byte_xor(hex_str):
    cipher_bytes = bytes.fromhex(hex_str)
    best_score = 0
    best_key = None
    best_text = None

    for key_candidate in range(256):
        plaintext_candidate = single_byte_xor(cipher_bytes, key_candidate)
        try:
            score = score_text(plaintext_candidate)
            if score > best_score:
                best_score = score
                best_key = key_candidate
                best_text = plaintext_candidate.decode('utf-8', errors='ignore')
        except UnicodeDecodeError:
            continue
    return best_key, best_text, best_score



# 主程序
# =========================
if __name__ == "__main__":
    print("===== Cryptopals Set 1 =====")

    # ---------- 第1题 ----------
    print("\n[题1] 十六进制转Base64")
    hex_str = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    b64_result = hex_to_base64(hex_str)
    print("输出：", b64_result)
    print("应为：SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t")

    # ---------- 第2题 ----------
    print("\n[题2] 固定异或")
    h1 = "1c0111001f010100061a024b53535009181c"
    h2 = "686974207468652062756c6c277320657965"
    xor_result = fixed_xor(h1, h2)
    print("输出：", xor_result)
    print("应为：746865206b696420646f6e277420706c6179")

    # ---------- 第3题 ----------
    print("\n[题3] 单字节异或破解")
    hex_cipher = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    key, plaintext, _ = break_single_byte_xor(hex_cipher)
    print(f"密钥: '{chr(key)}' (ASCII: {key})")
    print("解密结果：", plaintext)

   