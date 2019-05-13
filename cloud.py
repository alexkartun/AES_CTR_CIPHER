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
        self.__cipher_text = bytearray(self.__encrypt(plain_text))

    def __create_cipher(self, init_values):
        """
        creating aes cipher via ctr mode and 256 bit key
        :param init_values: initial value of counter
        :return: aes cipher
        """
        counter = Counter.new(COUNTER_BIT_SIZE, self.__nonce, initial_value=init_values)
        return AES.new(self.__key, AES.MODE_CTR, counter=counter)

    def __encrypt(self, data, init_values=1):
        """
        encrypt via ctr mode
        :param data: data to be encrypted
        :param init_values: initial value of counter (default is 1)
        :return: encrypted data
        """
        cipher = self.__create_cipher(init_values)
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
        return chr(self.__cipher_text[position])

    def Write(self, position=0, new_byte='\x33'):
        """
        write new byte to cipher_text at specific position user provided
        :param position: position of new byte
        :param new_byte: new byte we want to decrypt and write to cipher_text at specific position
        :return: old encrypted byte at position
        """
        old_byte = self.Read(position)
        block_index = (position / AES.block_size) + 1
        block_offset = position % AES.block_size
        empty_aes_block = bytearray(AES.block_size)     # empty aes block
        empty_aes_block[block_offset] = new_byte        # set new byte in empty block at offset
        # encrypt the block
        encrypted_aes_block = bytearray(self.__encrypt(str(empty_aes_block), init_values=block_index))
        # set encrypted byte from encrypted block to cipher_text byte array at position provided
        self.__cipher_text[position] = encrypted_aes_block[block_offset]

        return old_byte
