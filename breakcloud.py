# constants
# we know that, cipher_byte = F(k, CTR) xor plain_byte, so purpose of zero_byte is to reveal F(k, CTR) value
ZERO_BYTE = b'\x00'
OUTPUT_PATH = 'plain.txt'


def breakcloud(cloud):
    """
    breaking the cloud cipher by using read/write cloud api functions (vurnable functions)
    :param cloud: cloud that adversary want to break
    :return: None. writing result plain_text to file (OUTPUT_PATH)
    """
    position = 0
    plain_text = []

    # iterate over all the cipher_text till position (counter) will overflow the cipher_text length
    while True:
        cipher_byte = cloud.write(position, ZERO_BYTE)  # get cipher byte and write ZERO_BYTE
        decrypted_zero_byte = cloud.read(position)  # read decrypted ZERO_BYTE which value is F(k, CTR)
        if not cipher_byte or not decrypted_zero_byte:  # output check
            break

        # plain_byte = F(k, CTR) xor cipher_byte
        plain_text.append(chr(ord(decrypted_zero_byte) ^ ord(cipher_byte)))
        position += 1

    with open(OUTPUT_PATH, mode='wb') as f:  # write to file all the plain_text content
        f.write(''.join(plain_text))
