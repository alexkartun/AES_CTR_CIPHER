from Crypto import Random
from Crypto.Util import Counter
import Crypto.Cipher.AES as AES

NONCE_BYTE_SIZE = 8
COUNTER_BIT_SIZE = 64
KEY_BYTE_SIZE = 32


# static key (testing)
# self.key = b'\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c\x2b\x7e\x15' \
# b'\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c'
# counter = Counter.new(128, initial_value=0)


class Cloud:
    """ Cloud service that stores and encrypts user's data """

    def __init__(self, filename):
        self.key = Random.get_random_bytes(KEY_BYTE_SIZE)
        self.nonce = Random.get_random_bytes(NONCE_BYTE_SIZE)
        with open(filename, mode='rb') as f:
            plain_text = f.read()
            if plain_text:  # checking if plain text is not empty
                self.cipher_text = self.encrypt(plain_text)
            else:
                self.cipher_text = None

    def create_cipher(self):
        """
        creating aes cipher via ctr mode and 256 bit key
        :return: aes cipher
        """
        counter = Counter.new(COUNTER_BIT_SIZE, self.nonce)
        return AES.new(self.key, AES.MODE_CTR, counter=counter)

    def encrypt(self, text):
        """
        encrypt via ctr mode
        :param text: text to be encrypted
        :return: encrypted text
        """
        cipher = self.create_cipher()
        return cipher.encrypt(text)

    def read(self, position=0):
        """
        read the encrypted byte from cipher_text at specific position user provided
        :param position: encrypted byte's location
        :return: encrypted byte
        """
        # input check and overflow check
        if not self.cipher_text or position < 0 or position >= len(self.cipher_text):
            return None

        return chr(ord(self.cipher_text[position]))

    def write(self, position=0, new_byte='\x33'):
        """
        write the plain byte to cipher_text at specific position user provided
        :param position: encrypted byte's location user provided
        :param new_byte: new plain byte we want to decrypt and write to cipher_text
        :return: old encrypted byte at position
        """
        # input check and overflow check
        if not new_byte or not self.cipher_text or position < 0 or position >= len(self.cipher_text):
            return None

        old_byte = self.read(position)
        plain_text = self.encrypt(self.cipher_text)  # decrypt back to plain_text
        plain_text = plain_text[:position] + new_byte + plain_text[position + 1:]  # change byte in position
        self.cipher_text = self.encrypt(plain_text)  # encrypt back to cypher_text

        return old_byte
