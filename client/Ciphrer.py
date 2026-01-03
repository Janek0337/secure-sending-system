from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import secrets

class AES_cipherer:
    def __init__(self):
        self.block_size = 16

    def pad_data(self, data: bytes, block_size: int):
        missing_size = block_size - len(data) % block_size
        result_data = data + bytes([missing_size] * missing_size)

        return result_data

    def unpad_data(self, padded_data: bytes):
        padding_len = int(padded_data[-1])

        expected_padding = bytes([padding_len] * padding_len)
        if expected_padding != padded_data[-padding_len:]:
            raise ValueError("Incorrect padding")
            
        unpadded_data = padded_data[:-padding_len]
        return unpadded_data
        

    def encrypt_data(self, data: bytes, key=None):
        """
        returns encrypted data with block_size iv attached at the beginning
        """
        if key is None:
            key = secrets.token_bytes(32) # 32B = 256 bit
        iv = get_random_bytes(self.block_size)

        cipher = AES.new(key=key, mode=AES.MODE_CBC, iv=iv)
        padded_data = self.pad_data(data, self.block_size)
        encrypted_data = cipher.encrypt(padded_data)
        full_data = iv + encrypted_data
        return (full_data, key)
    
    def decrypt_data(self, data: bytes, key: bytes):
        iv = data[:self.block_size]
        cipher = AES.new(key=key, mode=AES.MODE_CBC, iv=iv)

        decrypted_data = cipher.decrypt(data[self.block_size:])
        unpadded_data = self.unpad_data(decrypted_data)

        return unpadded_data