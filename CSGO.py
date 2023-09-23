import argparse
import base64
import binascii
import hashlib
import hmac

import hexdump
import javaobj.v2 as javaobj
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from FlowAnalyzer import FlowAnalyzer


def signal():
    print('''

  _    ____                                      
 | |  |___ \                                     
 | |__  __) |_ __   __ _ _   _  __ _ _ __   __ _ 
 | '_ \|__ <| '_ \ / _` | | | |/ _` | '_ \ / _` |
 | |_) |__) | | | | (_| | |_| | (_| | | | | (_| |
 |_.__/____/|_| |_|\__, |\__,_|\__,_|_| |_|\__, |
                    __/ |                   __/ |
                   |___/                   |___/ 
                                                    作者：本光
    ''')
    temp = input("\033[1;34m输入任意键继续\033[0m")


0


def print_separator(func):
    def wrapper(*args, **kwargs):
        result = func(*args, **kwargs)
        print("\033[1;31m------------------------------------------------------------------------------\033[0m")
        return result

    return wrapper


def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", type=str, default=None, required=True,
                        help="输入JAVA序列化文件 .cobaltstrike.beacon_keys 路径")
    parser.add_argument("-t", type=str, default=None, required=True,
                        help="输入cs元数据(cookie值)")
    parser.add_argument('--pcap', type=str, default=None, required=False,
                        help='输入流量包位置')
    return parser.parse_args()


def get_RSA_PriKey(SerializeKeyPath):
    with open(SerializeKeyPath, "rb") as fd:
        pobj = javaobj.load(fd)
    privateKey = pobj.array.value.privateKey.encoded.data
    publicKey = pobj.array.value.publicKey.encoded.data

    privateKey = (
            b"-----BEGIN PRIVATE KEY-----\n"
            + base64.encodebytes(bytes(map(lambda x: x & 0xFF, privateKey)))
            + b"-----END PRIVATE KEY-----"
    )
    publicKey = (
            b"-----BEGIN PUBLIC KEY-----\n"
            + base64.encodebytes(bytes(map(lambda x: x & 0xFF, publicKey)))
            + b"-----END PUBLIC KEY-----"
    )
    print(privateKey := privateKey.decode())
    print(publicKey := publicKey.decode())
    return publicKey, privateKey


def create_PK_Cipher(privateKey):
    privateKey = RSA.import_key(privateKey.encode())
    n_bytes = privateKey.n.bit_length() // 8
    cipher = PKCS1_v1_5.new(privateKey)
    return cipher, n_bytes


def private_decrypt(cipher_text, privateKey):
    cipher, n_bytes = create_PK_Cipher(privateKey)
    cipher_text = base64.b64decode(cipher_text.encode())
    return b''.join(
        cipher.decrypt(cipher_text[i: i + n_bytes], 0)
        for i in range(0, len(cipher_text), n_bytes)
    )


def get_AES_HMAC_Key(SerializeKeyPath, rsa_cipher_text):
    _, privateKey = get_RSA_PriKey(SerializeKeyPath)

    if not (plain_text := private_decrypt(rsa_cipher_text, privateKey)):
        print("[+]: 解密错误, 可能是RSA_Cipher_Text或者密钥有误!")
        exit(-1)

    raw_aes_keys = plain_text[8:24]
    raw_aes_hash256 = hashlib.sha256(raw_aes_keys)
    digest = raw_aes_hash256.digest()
    aes_key = digest[:16]
    hmac_key = digest[16:]
    return aes_key, hmac_key, plain_text


def compare_mac(mac, mac_verif):
    if mac == mac_verif:
        return True
    if len(mac) != len(mac_verif):
        print("invalid MAC size")
        return False
    result = 0
    for x, y in zip(mac, mac_verif):
        result |= x ^ y
    return result == 0


def decrypt(encrypted_data, iv_bytes, signature, shared_key, hmac_key):
    if not compare_mac(hmac.new(hmac_key, encrypted_data, digestmod="sha256").digest()[0:16], signature):
        print("message authentication failed")
        return

    cypher = AES.new(shared_key, AES.MODE_CBC, iv_bytes)
    data = cypher.decrypt(encrypted_data)
    return data


@print_separator
def CS_decode(SHARED_KEY, HMAC_KEY, encrypt_data):
    encrypt_data_length = int.from_bytes(encrypt_data[0:4], byteorder='big', signed=False)
    encrypt_data_l = encrypt_data[4:len(encrypt_data)]

    data1 = encrypt_data_l[0:encrypt_data_length - 16]
    signature = encrypt_data_l[encrypt_data_length - 16:encrypt_data_length]
    iv_bytes = bytes("abcdefghijklmnop", 'utf-8')

    if (dec := decrypt(data1, iv_bytes, signature, SHARED_KEY, HMAC_KEY)) is None:
        return 0
    # try:
    # dec = decrypt(data1, iv_bytes, signature, SHARED_KEY, HMAC_KEY)
    # try:
    #     if (result := chardet.detect(dec)) and result["encoding"] in ["GB2312", "UTF-16", "utf-8", "UTF-8-SIG",
    #                                                                   "ascii"] and result["confidence"] > 0.8:
    #         print(dec.decode(result.get("encoding"), errors="ignore"))
    # except:
    #     print(dec)
    try:
        hexdump.hexdump(dec)
    except:
        print(dec)

    tmp = input("\033[1;34m输入任意键继续\033[0m")


def flow_analyse(flowPath) -> list:
    lst = []
    display_filter = "http"

    jsonPath = FlowAnalyzer.get_json_data(flowPath, display_filter=display_filter)
    for count, http in enumerate(FlowAnalyzer(jsonPath).generate_http_dict_pairs(), start=1):

        request, response = http.request, http.response
        if request:
            request_num, header, file_data, time_epoch = request.frame_num, request.header, request.file_data, request.time_epoch
            to_processed_data = file_data.hex().encode()
            if to_processed_data != b"":
                lst.append(to_processed_data)

    return lst


if __name__ == '__main__':
    signal()

    args = parse_arguments()

    SerializeKeyPath = args.f
    rsa_cipher_text = args.t
    aes_key, hmac_key, plain_text = get_AES_HMAC_Key(SerializeKeyPath, rsa_cipher_text)
    print(f"\033[32;1mAES key: {aes_key.hex()}\033[0m")
    print(f"\033[32;1mHMAC key: {hmac_key.hex()}\033[0m")
    hexdump.hexdump(plain_text)

    if (tmp := input("\033[1;34m是否进行行为分析(1/0):\033[0m")) == "0":
        exit("\033[1;31m再见\033[0m")
    else:
        flowPath = args.pcap
        SHARED_KEY = binascii.unhexlify(aes_key.hex())
        HMAC_KEY = binascii.unhexlify(hmac_key.hex())
        for data in flow_analyse(flowPath):
            CS_decode(SHARED_KEY, HMAC_KEY, binascii.unhexlify(data))
