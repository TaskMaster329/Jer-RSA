import socket
import argparse
import os
from tqdm import tqdm
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


def encrypt_file(file_path, public_key):
    cipher = PKCS1_OAEP.new(public_key)

    chunk_size = 190  # for RSA 2048 OAEP
    encrypted_data = b""

    with open(file_path, "rb") as f:
        data = f.read()

    with tqdm(
        total=len(data),
        unit="B",
        unit_scale=True,
        desc="Encrypting"
    ) as progress:

        for i in range(0, len(data), chunk_size):
            chunk = data[i:i + chunk_size]

            encrypted_chunk = cipher.encrypt(chunk)

            encrypted_data += encrypted_chunk

            progress.update(len(chunk))

    return encrypted_data


def main():
    parser = argparse.ArgumentParser(
        description="RSA File Transfer Client"
    )

    parser.add_argument(
        "--host",
        required=True,
        help="Server IP address"
    )

    parser.add_argument(
        "--port",
        type=int,
        default=9000,
        help="Server port"
    )

    parser.add_argument(
        "--transfer",
        required=True,
        help="File to transfer"
    )

    parser.add_argument(
        "--key",
        default="public.pem",
        help="Public RSA key"
    )

    args = parser.parse_args()

    if not os.path.exists(args.transfer):
        print("[-] File not found")
        return

    try:
        with open(args.key, "rb") as f:
            public_key = RSA.import_key(f.read())

    except Exception as e:
        print(f"[-] Failed to load public key: {e}")
        return

    try:
        encrypted_data = encrypt_file(
            args.transfer,
            public_key
        )
        filename = os.path.basename(args.transfer).encode()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        print(f"[+] Connecting to {args.host}:{args.port}")

        sock.connect((args.host, args.port))

        print("[+] Connected")

        # filename length
        sock.send(len(filename).to_bytes(2, "big"))

        # filename
        sock.send(filename)

        # encrypted payload size
        sock.send(len(encrypted_data).to_bytes(8, "big"))

        # encrypted data
        with tqdm(
            total=len(encrypted_data),
            unit="B",
            unit_scale=True,
            desc="Sending"
        ) as progress:

            for i in range(0, len(encrypted_data), 4096):
                chunk = encrypted_data[i:i + 4096]

                sock.sendall(chunk)

                progress.update(len(chunk))

        print("[+] File successfully sent")

    except Exception as e:
        print(f"[-] Transfer error: {e}")

    finally:
        try:
            sock.close()

        except:
            pass


if __name__ == "__main__":
    main()
