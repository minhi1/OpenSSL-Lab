import sys
import math
from cryptography.hazmat.primitives import serialization

priv_key_filename = ""
pub_key_filename = ""

def extract():
    # Read the private key file
    try:
        with open(priv_key_filename, "rb") as priv_key_file:
            private_key = serialization.load_pem_private_key(
                priv_key_file.read(),
                password=None,
            )
    except Exception as err:
        print(f"Error opening {priv_key_filename}. {err}")
        return

    # 2. Extract the values of private key 
    # Decoding the DER structure
    numbers = private_key.private_numbers()

    # 3. Access the mathematical components
    # Doc: https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateNumbers
    n = numbers.public_numbers.n
    e = numbers.public_numbers.e
    d = numbers.d
    p = numbers.p
    q = numbers.q
    dmp1 = numbers.dmp1 # CRT coefficient (d mod (p - 1)) 
    dmq1 = numbers.dmq1 # d mod (q - 1)
    iqmp = numbers.iqmp # q^(-1) mod p

    print(f"{'='*9} RSA Key Components {'='*9}")
    print(f"[*] Modulus n:          {hex(n)}") 
    print(f"[*] Prime p:            {hex(p)}")
    print(f"[*] Prime q:            {hex(q)}")
    print(f"[*] Encryption key e:   {hex(e)}")
    print(f"[*] Decryption key d:   {hex(d)}")
    print(f"[*] d % (p - 1):        {hex(dmp1)}")
    print(f"[*] d % (q - 1):        {hex(dmq1)}")
    print(f"[*] q^(-1) % p:         {hex(iqmp)}")
    
    pub_n = None
    pub_e = None

    # Read the public key file (if have)
    if pub_key_filename != "":
        try:
            with open(pub_key_filename, "rb") as pub_key_file:
                public_key = serialization.load_pem_public_key(
                                pub_key_file.read()
                             )
        except Exception as error:
            print(f"Error opening {pub_key_filename}. {error}")
            return (n, p, q, e, d), (None, None)

        # Extract the values of public key 
        pub_numbers = public_key.public_numbers()
        pub_n = pub_numbers.n
        pub_e = pub_numbers.e

    return (n, p, q, e, d), (pub_n, pub_e) 

def print_verify_result(cond):
    return '[✓]' if cond else '[X]'

def verify(n, p, q, e, d, pub_n, pub_e):
    print(f"\n{'='*9} Verifying Key Components {'='*9}")
    
    checks = {
        # f"Verify n and e of {priv_key_filename} and {pub_key_filename}": 1, 
        "Verify n = p * q": n == p * q,
        "Verify (e * d) % phi = 1": (e*d) % ((p-1)*(q-1)) == 1,
        "Verify gcd(e, phi) = 1": math.gcd(e,(p-1)*(q-1)) == 1
    }
    
    if pub_n is not None and pub_e is not None:
        if pub_n != n:
            print(f"!!! Modulus n of {priv_key_filename} and {pub_key_filename} not matched")
            return
        if pub_e != e:
            print(f"!!! Encryption key e of {priv_key_filename} and {pub_key_filename} not matched")
            return
        checks = {f"Verify n and e of {priv_key_filename} and {pub_key_filename}": 1, **checks}
    
    passed = 0
    
    for desc, res in checks.items():
        if res == True:
            passed = passed + 1
        print(f"{print_verify_result(res)} {desc}")
    
    if passed == len(checks):
        print("🎉 Valid RSA Key Pair")
    
if __name__ == "__main__":
    # Read input arguments
    if len(sys.argv) < 2:
        print("Usage: python3 key_check.py <private_key_file> [<public_key_file>]")
    else:
        priv_key_filename = sys.argv[1]
        if len(sys.argv) >= 3:
            pub_key_filename = sys.argv[2]
    
        # Extract information
        (n, p, q, e, d), (pub_n, pub_e) = extract()

        # Verify accuracy
        verify(n, p, q, e, d, pub_n, pub_e)
