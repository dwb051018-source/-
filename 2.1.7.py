from Crypto.Cipher import AES

def PKCS_7_padding_validation(padded_message: bytes) -> bytes:
    # 最后一个字节表示填充的字节数
    last_byte = padded_message[-1]

    # 如果填充字节数大于消息长度 → 无效
    if last_byte > len(padded_message):
        raise ValueError('Padding is Invalid')

    # 检查最后 last_byte 个字节是否都等于 last_byte
    for x in range(1, last_byte + 1):
        if padded_message[-x] != last_byte:
            raise ValueError('Padding is Invalid')

    # 如果合法，返回去掉填充的明文
    return padded_message[:-last_byte]


if __name__ == "__main__":
    test_cases = [
        b'ICE ICE BABY\x04\x04\x04\x04',
        b'ICE ICE BABY\x05\x05\x05\x05',
        b'ICE ICE BABY\x01\x02\x03\x04'
    ]

    for t in test_cases:
        try:
            print(PKCS_7_padding_validation(t))
        except ValueError as e:
            print(e)
