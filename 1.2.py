
import os

hex_cipher = 'F96DE8C227A259C87EE1DA2AED57C93FE5DA36ED4EC87EF2C63AAE5B9A7EFFD673BE4ACF7BE8923CAB1ECE7AF2DA3DA44FCF7AE29235A24C963FF0DF3CA3599A70E5DA36BF1ECE77F8DC34BE129A6CF4D126BF5B9A7CFEDF3EB850D37CF0C63AA2509A76FF9227A55B9A6FE3D720A850D97AB1DD35ED5FCE6BF0D138A84CC931B1F121B44ECE70F6C032BD56C33FF9D320ED5CDF7AFF9226BE5BDE3FF7DD21ED56CF71F5C036A94D963FF8D473A351CE3FE5DA3CB84DDB71F5C17FED51DC3FE8D732BF4D963FF3C727ED4AC87EF5DB27A451D47EFD9230BF47CA6BFEC12ABE4ADF72E29224A84CDF3FF5D720A459D47AF59232A35A9A7AE7D33FB85FCE7AF5923AA31EDB3FF7D33ABF52C33FF0D673A551D93FFCD33DA35BC831B1F43CBF1EDF67F0DF23A15B963FE5DA36ED68D378F4DC36BF5B9A7AFFD121B44ECE76FEDC73BE5DD27AFCD773BA5FC93FE5DA3CB859D26BB1C63CED5CDF3FE2D730B84CDF3FF7DD21ED5ADF7CF0D636BE1EDB79E5D721ED57CE3FE6D320ED57D469F4DC27A85A963FF3C727ED49DF3FFFDD24ED55D470E69E73AC50DE3FE5DA3ABE1EDF67F4C030A44DDF3FF5D73EA250C96BE3D327A84D963FE5DA32B91ED36BB1D132A31ED87AB1D021A255DF71B1C436BF479A7AF0C13AA14794'
def read_hex_from_file(fname="ctext_hex.txt"):
    if not os.path.exists(fname):
        return None
    with open(fname, "r", encoding="utf-8") as f:
        s = "".join([line.strip() for line in f])
    s = s.replace(" ", "").replace("0x", "").replace("\n","").replace("\r","")
    return s

# 英文评分函数（基于字符频率与不可打印惩罚）
ENGLISH_FREQ_ORDER = " etaoinshrdlcumwfgypbvkjxqz"
def score_english(bs: bytes):
    try:
        text = bs.decode("latin1")
    except:
        return float("-inf")
    score = 0.0
    for ch in text:
        cl = ch.lower()
        if cl in ENGLISH_FREQ_ORDER:
            score += (len(ENGLISH_FREQ_ORDER) - ENGLISH_FREQ_ORDER.index(cl))
        if ch in ".,'\";:-?!()":
            score += 3
        if ord(ch) < 32 and ch not in "\n\r\t":
            score -= 100
        if ch.isdigit():
            score -= 5
    return score

def break_single_byte_xor(block: bytes):
    best_k = None
    best_pt = None
    best_score = float("-inf")
    for k in range(256):
        pt = bytes([b ^ k for b in block])
        s = score_english(pt)
        if s > best_score:
            best_k, best_pt, best_score = k, pt, s
    return best_k, best_pt, best_score

def break_with_keysize(data: bytes, keysize: int):
    # 转置字节：构造每个密钥位置对应的列
    transposed = []
    for i in range(keysize):
        col = bytes([data[j] for j in range(i, len(data), keysize)])
        transposed.append(col)
    key_bytes = bytearray()
    for col in transposed:
        kbyte, _, _ = break_single_byte_xor(col)
        key_bytes.append(kbyte)
    plaintext = bytes([data[i] ^ key_bytes[i % keysize] for i in range(len(data))])
    return bytes(key_bytes), plaintext, score_english(plaintext)

def crack_repeating_xor(hex_ciphertext: str, min_k=1, max_k=13):
    data = bytes.fromhex(hex_ciphertext)
    cand = []
    for k in range(min_k, max_k+1):
        key, pt, sc = break_with_keysize(data, k)
        cand.append({'keysize': k, 'key': key, 'plaintext': pt, 'score': sc})
    cand.sort(key=lambda x: x['score'], reverse=True)
    return cand

def main():
    global hex_cipher
    if hex_cipher is None:
        hex_cipher = read_hex_from_file("ctext_hex.txt")
        if not hex_cipher:
            print("未在 ctext_hex.txt 中找到密文，请把完整十六进制密文放到该文件，或把 hex_cipher 变量直接赋值为密文字符串。")
            return
    results = crack_repeating_xor(hex_cipher, 1, 13)
    best = results[0]
    print("Best keysize:", best['keysize'])
    print("Key (bytes):", best['key'])
    try:
        print("Key (utf-8):", best['key'].decode('utf-8', errors='replace'))
    except:
        pass
    print("Score:", best['score'])
    print("\nPlaintext (first 2000 chars):\n")
    print(best['plaintext'].decode('utf-8', errors='replace')[:2000])
    with open("recovered_plaintext.txt", "wb") as f:
        f.write(best['plaintext'])
    print("\n已把完整明文写入 recovered_plaintext.txt")

if __name__ == "__main__":
    main()
