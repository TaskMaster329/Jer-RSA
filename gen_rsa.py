#!/usr/bin/env python3

import argparse
from Crypto.PublicKey import RSA


def generate_keys(bits, private_key, public_key):
    try:
        print(f"[+] Generating RSA key pair ({bits} bits)...")

        key = RSA.generate(bits)

        with open(private_key, "wb") as f:
            f.write(key.export_key())

        with open(public_key, "wb") as f:
            f.write(key.publickey().export_key())

        print(f"[+] Private key saved to: {private_key}")
        print(f"[+] Public key saved to:  {public_key}")
        print("[+] RSA keys generated successfully")

    except Exception as e:
        print(f"[ERROR] Failed to generate keys: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="RSA key pair generator for secure file transfer"
    )

    parser.add_argument(
        "--bits",
        type=int,
        default=2048,
        help="RSA key size in bits (default: 2048)"
    )

    parser.add_argument(
        "--private",
        default="private.pem",
        help="Output private key file (default: private.pem)"
    )

    parser.add_argument(
        "--public",
        default="public.pem",
        help="Output public key file (default: public.pem)"
    )

    args = parser.parse_args()

    generate_keys(
        bits=args.bits,
        private_key=args.private,
        public_key=args.public
    )


if __name__ == "__main__":
    main()
