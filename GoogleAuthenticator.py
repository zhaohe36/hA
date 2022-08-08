# -*- codeing = utf-8 -*-
# @Time :2022/8/7 22:53
import time
import struct
import base64
import hashlib
import hmac
from qrcode import QRCode
from qrcode import constants

"""一定要搞清，网上的TOTP和谷歌的secret都是base32编码过的，也就是说密钥解码后才是原文
    代码主要演示了如何处理TOTP算法，如何进行数据处理和转换以及二维码的生成与处理
    实际应用需选择pyotp，方便快捷
"""


def byte_secret(sc) -> bytes:  # base64要求字符串必须为8的倍数，不足部分使用 = 补全
    secret = sc
    missing_padding = len(secret) % 8
    if missing_padding != 0:
        secret += '=' * (8 - missing_padding)
    return base64.b32decode(secret, casefold=True)


oriSecret = "ddddd"
SecretofBS32 = base64.b32encode(oriSecret.encode('utf-8'))  # 密钥的BASE32码 如果不用utf-8的话会导致b32编码过程中报错
print("BASE32的密钥:"f'{SecretofBS32.decode("utf-8")}')
# K = base64.b32decode(SecretofBS32,True) #真正的密钥
K = byte_secret(SecretofBS32)  # 真正的密钥
C = struct.pack(">Q", int(time.time()) // 30)
H = hmac.new(K, C, hashlib.sha1).digest()
offset = H[-1] & 15
DynamicPasswd = str((struct.unpack(">I", H[offset:offset + 4])[0] & 0x7fffffff) % 1000000)
TOTP = DynamicPasswd
while len(TOTP) < 6:
    TOTP = str(0) + TOTP
print("TOKEN:"f'{TOTP}')

num = input("输入1选择生成二维码")
if num == "1":
    qr = QRCode(version=1,
                error_correction=constants.ERROR_CORRECT_L,
                box_size=25,
                border=4, )
    content = "otpauth://totp/test@test.com?secret=" + str(SecretofBS32.decode("utf-8"))
    qr.add_data(content)
    qr.make(fit=True)
    img = qr.make_image()
    img.save('2.png')
