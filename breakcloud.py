OUTPUT_PATH = 'plain.txt'
ZERO_BYTE = b'\x00'


def breakcloud(cloud):
    """
    breaking the cloud cipher by using read/write cloud api functions (vurnable functions)
    :param cloud: cloud that adversary want to break
    :return: None. writing result plain_text to file (OUTPUT_PATH)
    """
    position = 0
    cipher_length = cloud.Length()
    plain_text = bytearray(cipher_length)
    # iterate over all the cipher_text till position (counter) will overflow the cipher_text length
    while position < cipher_length:
        c = cloud.Write(position, ZERO_BYTE)            # encrypt zero byte
        m_tag = cloud.Read(position)                    # m_tag = F(k, CTR) xor 0 = F(k, CTR)
        plain_text[position] = ord(m_tag) ^ ord(c)      # m_b = m_tag xor c
        position += 1

    with open(OUTPUT_PATH, mode='wb') as f:     # write to file all the plain_text content
        f.write(plain_text)
