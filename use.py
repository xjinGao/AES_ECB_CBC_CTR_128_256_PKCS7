import base64
from usr import mpyaes
from ucryptolib import aes
from uos import urandom


class AES_CBC_PKCS7:
    def __init__(self, key, IV=None):
        if IV is None:
            IV = mpyaes.generate_IV(16)
        self.key = key
        self.IV = IV
        self.cipher = mpyaes.new(self.key, mpyaes.MODE_CBC, IV)

    def encrypt(self, data):
        """
        对数据进行 AES-CBC 加密并返回 Base64 编码后的密文。
        """
        self.cipher.encrypt(data)
        base64_encrypted_data = base64.b64encode(data)
        return base64_encrypted_data

    def decrypt(self, base64_encrypted_data):
        """
        对 Base64 编码的密文进行 AES-CBC 解密并返回原始数据。
        """
        encrypted_data = bytearray(base64.b64decode(base64_encrypted_data))
        return self.cipher.decrypt(encrypted_data)


# 使用示例
key = mpyaes.generate_key(16)  # AES-128, 使用16字节的密钥
data = bytearray("Hello, MicroPython!")

aes_cbc_pkcs5 = AES_CBC_PKCS7(key)

encrypted_data_base64 = aes_cbc_pkcs5.encrypt(data)
print("加密后的数据（Base64 编码）:", encrypted_data_base64)

decrypted_data = aes_cbc_pkcs5.decrypt(encrypted_data_base64)
print("解密后的原始数据:", decrypted_data)
