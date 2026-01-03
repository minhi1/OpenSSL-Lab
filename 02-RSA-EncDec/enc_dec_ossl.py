# openssl/blob/master/include/openssl/rsa.h
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

OPENSSL_RSA_MAX_MODULUS_BITS = 16384
OPENSSL_RSA_SMALL_MODULUS_BITS = 3072
OPENSSL_RSA_MAX_PUBEXP_BITS = 64
RSA_PKCS1_PADDING_SIZE = 11


import os

def num_bits(num):
	return num.bit_length()

def rsa_padding_add_pkcs1_type_2(to_len: int, data: bytes) -> bytes:
    flen = len(data)

    # length checks
    if flen > to_len - RSA_PKCS1_PADDING_SIZE:
        raise ValueError("data too large for key size")
    if flen < 0:
        raise ValueError("invalid length")

    # output buffer
    to = bytearray(to_len)

    p = 0
    to[p] = 0x00
    p += 1
    to[p] = 0x02   # block type 2
    p += 1

    # number of padding bytes
    j = to_len - 3 - flen

    # generate non-zero random padding
    padding = bytearray(os.urandom(j))
    for i in range(j):
        while padding[i] == 0x00:
            padding[i] = os.urandom(1)[0]

    to[p:p+j] = padding
    p += j

    # separator
    to[p] = 0x00
    p += 1

    # message
    to[p:p+flen] = data

    return bytes(to)

def rsa_padding_check_pkcs1_type_2(em: bytes) -> bytes:
    """
    EM = 0x00 || 0x02 || PS || 0x00 || M
    """
    if len(em) < 11:
        raise ValueError("decryption error")

    if em[0] != 0x00 or em[1] != 0x02:
        raise ValueError("decryption error")

    # find 0x00 separator
    try:
        sep = em.index(0x00, 2)
    except ValueError:
        raise ValueError("decryption error")

    if sep < 10:  # PS must be at least 8 bytes
        raise ValueError("decryption error")

    return em[sep + 1:]


def public_encrypt_pkcs1_v15(data: bytes, rsa):
    if num_bits(rsa.n) > OPENSSL_RSA_MAX_MODULUS_BITS:
        raise Exception("MODULUS_TOO_LARGE")

    if rsa.n <= rsa.e:
        raise Exception("BAD_E_VALUE")

    if (num_bits(rsa.n) > OPENSSL_RSA_SMALL_MODULUS_BITS and
        num_bits(rsa.e) > OPENSSL_RSA_MAX_PUBEXP_BITS):
        raise Exception("BAD_E_VALUE")

    rsa_size = (num_bits(rsa.n) + 7) // 8

    em = rsa_padding_add_pkcs1_type_2(rsa_size, data)
    m = int.from_bytes(em, "big")

    c = pow(m, rsa.e, rsa.n)

    return c.to_bytes(rsa_size, "big")




def rsa_private_crt(c: int, rsa) -> int:
    """
    Compute m = c^d mod n using CRT
    """

    # m1 = c^dmp1 mod p
    m1 = pow(c % rsa.p, rsa.dmp1, rsa.p)

    # m2 = c^dmq1 mod q
    m2 = pow(c % rsa.q, rsa.dmq1, rsa.q)

    # h = (m1 - m2) * iqmp mod p
    h = (m1 - m2) % rsa.p
    h = (h * rsa.iqmp) % rsa.p

    # m = m2 + q * h
    m = m2 + rsa.q * h

    return m

def private_decrypt_pkcs1_v15(ciphertext: bytes, rsa) -> bytes:
    rsa_size = (rsa.n.bit_length() + 7) // 8

    if len(ciphertext) != rsa_size:
        raise ValueError("invalid ciphertext length")

    # 1️⃣ ciphertext → integer
    c = int.from_bytes(ciphertext, "big")

    if c >= rsa.n:
        raise ValueError("ciphertext too large")

    # 2️⃣ RSA CRT private operation
    m = rsa_private_crt(c, rsa)

    # 3️⃣ integer → fixed-size EM
    em = m.to_bytes(rsa_size, "big")

    # 4️⃣ PKCS#1 v1.5 unpadding
    return rsa_padding_check_pkcs1_type_2(em)

def load_rsa_private_key(pem_path: str, password: bytes | None = None):
    with open(pem_path, "rb") as f:
        pem_data = f.read()

    key = serialization.load_pem_private_key(
        pem_data,
        password=password,
        backend=default_backend()
    )

    if not isinstance(key, rsa.RSAPrivateKey):
        raise TypeError("Not an RSA private key")

    return key

class SimpleRSA:
    pass

def extract_rsa_params_from_private_key(key: rsa.RSAPrivateKey) -> SimpleRSA:
    nums = key.private_numbers()
    pub = nums.public_numbers

    r = SimpleRSA()
    r.n = pub.n
    r.e = pub.e
    r.d = nums.d
    r.p = nums.p
    r.q = nums.q
    r.dmp1 = nums.dmp1   # d mod (p-1)
    r.dmq1 = nums.dmq1   # d mod (q-1)
    r.iqmp = nums.iqmp   # q^{-1} mod p

    return r

def load_rsa_private_key(pem_path: str, password: bytes | None = None):
    with open(pem_path, "rb") as f:
        pem_data = f.read()

    key = serialization.load_pem_private_key(
        pem_data,
        password=password,
        backend=default_backend()
    )

    if not isinstance(key, rsa.RSAPrivateKey):
        raise TypeError("Not an RSA private key")

    return key

def load_rsa_public_key(pem_path: str):
    with open(pem_path, "rb") as f:
        pem_data = f.read()

    key = serialization.load_pem_public_key(
        pem_data,
        backend=default_backend()
    )

    if not isinstance(key, rsa.RSAPublicKey):
        raise TypeError("Not an RSA public key")

    nums = key.public_numbers()

    r = SimpleRSA()
    r.n = nums.n
    r.e = nums.e

    return r


import argparse
import sys

def main():
    parser = argparse.ArgumentParser(
        description="OpenSSL RSA Encryption and Decryption Python implementation"
    )

    parser.add_argument(
        "key",
        help="Public key (for encrypt) or private key (for decrypt) in PEM format"
    )
    parser.add_argument(
        "input",
        help="Input file (plaintext for encrypt, ciphertext for decrypt)"
    )

    parser.add_argument(
        "-out",
        dest="out",
        help="Output file (default: stdout)"
    )

    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--encrypt",
        action="store_true",
        help="Encrypt input"
    )
    mode.add_argument(
        "--decrypt",
        action="store_true",
        help="Decrypt input"
    )

    args = parser.parse_args()

    if args.encrypt:
        encrypt(args.key, args.input, args.out)
    elif args.decrypt:
        decrypt(args.key, args.input, args.out)


def encrypt(pubkey_path, plaintext_path, out_path=None):
    print("[*] Encryption mode")

    rsa_obj = load_rsa_public_key(pubkey_path)

    with open(plaintext_path, "rb") as f:
        plaintext = f.read()

    ciphertext = public_encrypt_pkcs1_v15(plaintext, rsa_obj)

    if out_path:
        with open(out_path, "wb") as f:
            f.write(ciphertext)
    else:
        print(ciphertext.hex())

def decrypt(privkey_path, ciphertext_path, out_path=None):
    print("[*] Decryption mode")

    key = load_rsa_private_key(privkey_path)
    rsa_obj = extract_rsa_params_from_private_key(key)

    with open(ciphertext_path, "rb") as f:
        ciphertext = f.read()

    plaintext = private_decrypt_pkcs1_v15(ciphertext, rsa_obj)

    if out_path:
        with open(out_path, "wb") as f:
            f.write(plaintext)
    else:
        sys.stdout.buffer.write(plaintext)


if __name__ == "__main__":
    main()