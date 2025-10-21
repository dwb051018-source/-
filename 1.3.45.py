import base64

# ========== 通用函数（从前面复用） ==========
def single_byte_xor(cipher_bytes, key):
    return bytes([b ^ key for b in cipher_bytes])

def score_text(text):
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


# ========== 第4题：检测单字节异或加密行 ==========
def detect_single_char_xor(file_path):
    import re
    best_overall = {'line': 0, 'score': 0, 'key': None, 'text': None}
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        for i, raw_line in enumerate(f, start=1):
            # 清理行内容，只保留十六进制字符
            line = re.sub(r'[^0-9A-Fa-f]', '', raw_line.strip())
            if not line:
                continue
            try:
                key, text, score = break_single_byte_xor(line)
                if score > best_overall['score']:
                    best_overall = {'line': i, 'score': score, 'key': key, 'text': text}
            except Exception:
                continue
    return best_overall



# ========== 第5题：重复密钥 XOR ==========
def repeating_key_xor(plaintext, key):
    """使用重复key进行异或加密"""
    result = bytes([p ^ key[i % len(key)] for i, p in enumerate(plaintext)])
    return result.hex()


# ========== 主函数（演示4、5题） ==========
if __name__ == "__main__":
    # ---- 第4题 ----

    file_path = "data4.txt"
    try:
        result = detect_single_char_xor(file_path)
        print(f"题4 被加密的行号: {result['line']}")
        print(f"题4 密钥: {chr(result['key'])} (ASCII: {result['key']})")
        print("题4 解密结果：", result['text'])
    except FileNotFoundError:
        print("未读取到data4.txt")

    # ---- 第5题 ----
    plaintext = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    key = b"ICE"
    ciphertext_hex = repeating_key_xor(plaintext, key)
    print("\n题5 加密结果：", ciphertext_hex)
    # 应输出：
    # 0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20
    # 430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f
