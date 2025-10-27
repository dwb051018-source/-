

from Crypto.Cipher import AES
import os

# ---------- 辅助函数 ----------
def pkcs7_pad(message: bytes, blocksize: int) -> bytes:
    """标准 PKCS#7 填充（包括当 len(message) % blocksize == 0 时填充一整块）。"""
    padlen = blocksize - (len(message) % blocksize)
    if padlen == 0:
        padlen = blocksize
    return message + bytes([padlen]) * padlen

def pkcs7_unpad(padded: bytes) -> bytes:
    """验证并去掉 PKCS#7 填充；若无效则抛出 ValueError。"""
    if not padded:
        raise ValueError("Empty input when unpadding")
    last = padded[-1]
    if last == 0 or last > len(padded):
        raise ValueError("Invalid PKCS#7 padding")
    if padded[-last:] != bytes([last]) * last:
        raise ValueError("Invalid PKCS#7 padding")
    return padded[:-last]

def random_bytes(n: int) -> bytes:
    return os.urandom(n)

# ---------- 全局参数 ----------
BLOCK_SIZE = 16
IV = random_bytes(BLOCK_SIZE)            # 随机 IV（对演示固定即可）
KEY = random_bytes(16)                  # 随机 key（对演示固定即可）

# ---------- 加密/解密 接口 ----------
def cbc_oracle(userdata: bytes, encrypt=True) -> bytes:
    """
    当 encrypt=True 时：构造 prefix + userdata + suffix (并对 '=' 和 ';' 做转义)
    然后返回 CBC-AES(key, iv).encrypt(padded_plaintext)
    当 encrypt=False 时：将传入的密文解密并返回原始明文（未去填充）
    """
    prefix = b'comment1=cooking%20MCs;userdata='
    suffix = b';comment2=%20like%20a%20pound%20of%20bacon'

    if encrypt:
        # 对用户输入中的 ';' 和 '=' 进行简单“转义”（你的原意）
        safe_userdata = userdata.replace(b';', b'";"').replace(b'=', b'"="')
        plain = prefix + safe_userdata + suffix
        padded = pkcs7_pad(plain, BLOCK_SIZE)
        cipher = AES.new(KEY, AES.MODE_CBC, IV)
        return cipher.encrypt(padded)
    else:
        cipher = AES.new(KEY, AES.MODE_CBC, IV)
        return cipher.decrypt(userdata)

def is_admin(ciphertext: bytes) -> bool:
    """解密并检查是否包含 ';admin=true;' — 注意去填充并捕获填充错误。"""
    try:
        plaintext_padded = cbc_oracle(ciphertext, encrypt=False)
        plaintext = pkcs7_unpad(plaintext_padded)
        return b';admin=true;' in plaintext
    except ValueError:
        # 填充无效或其它错误 -> 视为不包含 admin
        return False

# ---------- 计算 prefix 使用多少个完整块（更鲁棒的方法） ----------
def compute_prefix_block_count() -> int:
    """
    通过对比密文前若干个块在不同 userdata 下是否变化来推断 prefix 占了多少个完整块。
    返回 prefix 占据的块数量（整数 >=1）。
    """
    # 先得到只包含 prefix + suffix 的密文（userdata = b''）
    ct0 = cbc_oracle(b'')
    # 再对用户输入 1 字节和 2 字节分别加密，观察前几个块是否变化
    for try_len in range(1, BLOCK_SIZE + 2):
        ct = cbc_oracle(b'A' * try_len)
        # 找到第一个块不相同的位置
        # 按块比较
        for block_index in range(0, len(ct0) // BLOCK_SIZE):
            b0 = ct0[block_index*BLOCK_SIZE:(block_index+1)*BLOCK_SIZE]
            b1 = ct[block_index*BLOCK_SIZE:(block_index+1)*BLOCK_SIZE]
            if b0 != b1:
                # prefix 占用的完整块数就是 block_index
                return block_index
    # 保守返回 1（理论上不应该到这里）
    return 1

# ---------- 实际的 bitflipping 攻击 ----------
def cbc_bitflipping_attack() -> bool:
    # 目标：通过修改某个密文字节，使解密后包含 ;admin=true;
    prefix_blocks = compute_prefix_block_count()
    # 我们构造的目标 userdata：使用占位字符 'x'，之后我们在上一密文块中 flip 字节变成 ';' 或 '='
    target = b'xadminxtruex'
    # 先找到一个位置使得 target 完全位于某个完整数据块的开始（即我们可以通过翻转前一密文块来控制）
    # 简化做法：发送 min_add padding 使 target 开始于块边界
    pad_len = 0
    # 我们尝试添加 0..BLOCK_SIZE-1 个 A，让 target 对齐到块边界
    for i in range(BLOCK_SIZE):
        ct = cbc_oracle(b'A'*i + target)
        # 解密并查看明文（带填充）
        pt = cbc_oracle(ct, encrypt=False)
        # 不做去填充，仅判断 target 在解密明文中的位置
        # 先去掉 prefix + escaped userdata 的长度来找真正起始偏移不容易，直接通过检测 ciphertext 块是否包含 target（简单而鲁棒的方法）
        # 这里采用：找到 target 在解密结果中的偏移（不去填充），若找不到继续尝试
        try:
            pt_unpadded = pkcs7_unpad(pt)
        except ValueError:
            pt_unpadded = pt  # 若填充错误，也尝试原始 bytes（不关键）
        idx = pt_unpadded.find(target)
        if idx != -1 and idx % BLOCK_SIZE == 0:
            pad_len = i
            start_idx = idx
            break
    else:
        # 若未找到对齐的情况，仍选择最廉价的策略：任选一个密文，按常见示例操作（不过上面通常能找到）
        pad_len = 0
        ct = cbc_oracle(b'A'*pad_len + target)
        pt_unpadded = pkcs7_unpad(cbc_oracle(ct, encrypt=False))
        start_idx = pt_unpadded.find(target)
        if start_idx == -1:
            raise RuntimeError("未能定位 target 在明文中的位置")

    # 得到密文并进行翻转
    ct = cbc_oracle(b'A'*pad_len + target)
    # 计算 target 所在块索引（0-based）
    block_idx = start_idx // BLOCK_SIZE
    # previous block 在密文中的字节范围：
    prev_block_offset = (block_idx - 1) * BLOCK_SIZE
    if prev_block_offset < 0:
        raise RuntimeError("target 位于第一个块，无法通过翻转上一块实现")
    prev_block = bytearray(ct[prev_block_offset: prev_block_offset + BLOCK_SIZE])

    # 我们的 target 是 b'xadminxtruex'，要将 'x' -> ';' 或 '='
    # 找出 target 在其块内的相对位置
    offset_in_block = start_idx % BLOCK_SIZE
    # 对应要翻转的位置（相对 prev_block）
    # 要把 prev_block[i] 改为 prev_block[i] ^ (ord('x') ^ ord(';')) 等
    # 翻转位置列表（相对于 target 中）
    flips = {
        0: (offset_in_block + 0),   # x -> ;
        6: (offset_in_block + 6),   # x -> =
        11: (offset_in_block + 11)  # x -> ;
    }
    for pos_in_target, abs_pos in flips.items():
        # 计算 prev_block 中对应字节索引
        idx_in_prev = abs_pos - BLOCK_SIZE  # 因为 prev_block 对应解密后影响的块在解密时会 XOR 到下一块
        # 等价地：要影响明文中绝对位置 abs_pos，需要修改密文中同块的相同位置（上一块）
        idx_in_prev = abs_pos - (block_idx * BLOCK_SIZE) + BLOCK_SIZE  # 更直观的计算
        # 但上式太绕，简化：直接计算 prev_block 的索引：
        prev_index = abs_pos - block_idx * BLOCK_SIZE + (BLOCK_SIZE - BLOCK_SIZE)
        # 实际上 prev_block 索引是 abs_pos % BLOCK_SIZE
        prev_index = abs_pos % BLOCK_SIZE

        # 计算异或值
        prev_block[prev_index] ^= (ord(b'x') ^ ord(b';')) if pos_in_target in (0, 11) else (ord(b'x') ^ ord(b'='))

    # 构造新的密文：替换相应的上一块
    modified_ct = bytearray(ct)
    modified_ct[prev_block_offset:prev_block_offset + BLOCK_SIZE] = prev_block

    # 检查是否成功
    success = is_admin(bytes(modified_ct))
    # 打印调试信息
    print("prefix_blocks:", prefix_blocks, "pad_len:", pad_len, "target_start:", start_idx, "success:", success)
    if success:
        print("成功：解密文本包含 ';admin=true;'")
    else:
        print("失败：未检测到 ';admin=true;'")
    return success

# ---------- 主入口 ----------
if __name__ == "__main__":
    print("开始 CBC bit-flipping 攻击演示...")
    result = cbc_bitflipping_attack()
    print("最终结果:", result)
