# sign and verify messages using digital signatures 
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def read_private_key(file_path):
    with open(file_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
        )
        if (isinstance(private_key, rsa.RSAPrivateKey) == False):
            raise ValueError("The private key is not an RSA private key.")
    return private_key

def read_public_key(file_path):
    with open(file_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
        )
        if (isinstance(public_key, rsa.RSAPublicKey) == False):
            raise ValueError("The public key is not an RSA public key.")
    return public_key


def sign_message(private_key, message):
    numbers = private_key.private_numbers()
    d = numbers.d
    n = numbers.public_numbers.n
    k = (n.bit_length() + 7) // 8
    
    m_len = len(message)
    if (m_len > k - 11):
        raise ValueError("Message too long for RSA signature.")
    
    ps_len = k - m_len - 3
    padding_string = b'\xff' * ps_len
    padding_message = b'\x00\x01' + padding_string + b'\x00' + message
    
    
    m = int.from_bytes(padding_message, byteorder='big')
    s = pow(m, d, n)
    signature = s.to_bytes(k, byteorder='big')
    return signature
    
def read_message(file_path):
    with open(file_path, "rb") as message_file:
        message = message_file.read()
    return message

def print_signature(file_path, signature):
    with open(file_path, "wb") as sig_file:
        sig_file.write(signature)

def verify_signature(public_key, message, signature):
    public_numbers = public_key.public_numbers()
    e = public_numbers.e
    n = public_numbers.n
    k = (n.bit_length() + 7) // 8
    
    if len(signature) != k:
        return False
    s = int.from_bytes(signature, byteorder='big')
    m = pow(s, e, n)
    decrypted_message = m.to_bytes(k, byteorder='big')
    if decrypted_message[0:2] == b'\x00\x01':
        try:
            sep_index = decrypted_message.index(b'\x00', 2)
        except ValueError:
            return False
        recovered_message = decrypted_message[sep_index + 1:]
        return recovered_message == message
    return False

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Sign or verify a message using RSA digital signatures.")
    parser.add_argument("mode", choices=["sign", "verify"], help="Mode: sign or verify a message.")
    parser.add_argument("key_file", help="Path to the private key file (for signing) or public key file (for verifying).")
    parser.add_argument("message_file", help="Path to the message file.")
    parser.add_argument("signature_file", help="Path to the signature file (for saving or reading).")

    args = parser.parse_args()

    if args.mode == "sign":
        private_key = read_private_key(args.key_file)
        message = read_message(args.message_file)
        signature = sign_message(private_key, message)
        print_signature(args.signature_file, signature)
        print("Message signed and signature saved to", args.signature_file)

    elif args.mode == "verify":
        public_key = read_public_key(args.key_file)
        message = read_message(args.message_file)
        with open(args.signature_file, "rb") as sig_file:
            signature = sig_file.read()
        is_valid = verify_signature(public_key, message, signature)
        if is_valid:
            print("Signature Verified Successfully.")
        else:
            print("Signature Verification Failed.")