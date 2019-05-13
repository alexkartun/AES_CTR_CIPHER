# we know ctr mode encryption and decryption are the same operations, so encrypt cypher text will give you
# the original decrypted message
OUTPUT_PATH = 'plain.txt'


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
        cipher_byte = cloud.Read(position)      # get cipher byte
        _ = cloud.Write(position, cipher_byte)  # write cipher_byte
        plain_byte = cloud.Read(position)       # read the encrypted cipher_byte to get plain_byte
        plain_text[position] = plain_byte
        position += 1

    with open(OUTPUT_PATH, mode='wb') as f:     # write to file all the plain_text content
        f.write(plain_text)
