import socket
import argparse
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


def encrypt_file(file_path, public_key_path):
    with open(public_key_path, "rb") as f:
        public_key = RSA.import_key(f.read())

    cipher = PKCS1_OAEP.new(public_key)

    with open(file_path, "rb") as f:
        data = f.read()

    key_size = public_key.size_in_bytes()
    max_chunk = key_size - 42

    encrypted = b""
    for i in range(0, len(data), max_chunk):
        encrypted += cipher.encrypt(data[i:i + max_chunk])

    return encrypted


def main():
    parser = argparse.ArgumentParser(description="RSA File Transfer Client")

    parser.add_argument("--transfer", required=True, help="Path to file to send")
    parser.add_argument("--host", default="127.0.0.1", help="Server IP address")
    parser.add_argument("--port", type=int, default=9000, help="Server port")
    parser.add_argument("--key", default="public.pem", help="Path to public key file")

    args = parser.parse_args()

    file_path = args.transfer
    file_name = os.path.basename(file_path)

    print(f"[+] Target file: {file_path}")
    print(f"[+] Server: {args.host}:{args.port}")

    encrypted_data = encrypt_file(file_path, args.key)

    file_name_bytes = file_name.encode()
    header = len(file_name_bytes).to_bytes(2, "big")

    packet = header + file_name_bytes + encrypted_data

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((args.host, args.port))
        sock.sendall(packet)
        sock.close()

        print(f"[+] Transfer complete: {file_name}")

    except Exception as e:
        print(f"[-] Connection failed: {e}")


if __name__ == "__main__":
    main()
