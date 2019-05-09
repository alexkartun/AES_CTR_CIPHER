from Crypto import Random
from Crypto.Util import Counter
import Crypto.Cipher.AES as AES

NONCE_BYTE_SIZE = 8
COUNTER_BIT_SIZE = 64
KEY_BYTE_SIZE = 32


class Cloud:
    """ Cloud service that stores and encrypts user's data """

    def __init__(self, filename, key=Random.get_random_bytes(KEY_BYTE_SIZE),
                 nonce=Random.get_random_bytes(NONCE_BYTE_SIZE)):
        self.__key = key
        self.__nonce = nonce
        with open(filename, mode='rb') as f:
            plain_text = f.read()
        self.__cipher_text = self.__encrypt(plain_text)

    def __create_cipher(self):
        """
        creating aes cipher via ctr mode and 256 bit key
        :return: aes cipher
        """
        counter = Counter.new(COUNTER_BIT_SIZE, self.__nonce)
        return AES.new(self.__key, AES.MODE_CTR, counter=counter)

    def __encrypt(self, data):
        """
        encrypt via ctr mode
        :param data: data to be encrypted
        :return: encrypted data
        """
        cipher = self.__create_cipher()
        return cipher.encrypt(data)

    def Length(self):
        """
        calculate length of cipher_text, this is necessary so one would not read/write with an invalid position.
        :return: length of cipher_text
        """
        return len(self.__cipher_text)

    def Read(self, position=0):
        """
        read the encrypted byte from cipher_text at specific position user provided
        :param position: encrypted byte's location
        :return: encrypted byte
        """
        return chr(ord(self.__cipher_text[position]))

    def Write(self, position=0, new_byte='\x33'):
        """
        write the plain byte to cipher_text at specific position user provided
        :param position: encrypted byte's location user provided
        :param new_byte: new plain byte we want to decrypt and write to cipher_text
        :return: old encrypted byte at position
        """

        old_byte = self.Read(position)
        plain_text = self.__encrypt(self.__cipher_text)  # decrypt back to plain_text
        plain_text = plain_text[:position] + new_byte + plain_text[position + 1:]  # change byte in position
        self.__cipher_text = self.__encrypt(plain_text)  # encrypt back to cypher_text

        return old_byte
