# Copyright (c) Quectel Wireless Solution, Co., Ltd.All Rights Reserved.
#  
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#  
#     http://www.apache.org/licenses/LICENSE-2.0
#  
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

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
