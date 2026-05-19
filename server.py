import socket
import argparse
import traceback
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


def decrypt_data(encrypted_data, private_key):
    cipher = PKCS1_OAEP.new(private_key)
    key_size = private_key.size_in_bytes()

    decrypted = b""

    for i in range(0, len(encrypted_data), key_size):
        chunk = encrypted_data[i:i + key_size]
        try:
            decrypted += cipher.decrypt(chunk)
        except Exception as e:
            print(f"[-] Decryption block failed: {e}")
            continue

    return decrypted


def handle_client(conn, addr, private_key):
    print(f"\n[+] New connection from {addr}")

    try:
        # ---- read filename safely ----
        name_len_bytes = conn.recv(2)
        if len(name_len_bytes) < 2:
            print("[-] Invalid filename header")
            return

        name_len = int.from_bytes(name_len_bytes, "big")
        file_name = conn.recv(name_len).decode(errors="ignore")

        print(f"[+] Receiving file: {file_name}")

        # ---- read encrypted payload ----
        encrypted_data = b""
        while True:
            try:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                encrypted_data += chunk
            except Exception as e:
                print(f"[-] Receive error: {e}")
                break

        if not encrypted_data:
            print("[-] Empty payload received")
            return

        # ---- decrypt ----
        decrypted = decrypt_data(encrypted_data, private_key)

        # ---- save file safely ----
        try:
            with open(file_name, "wb") as f:
                f.write(decrypted)
            print(f"[+] File saved: {file_name}")
        except Exception as e:
            print(f"[-] File write error: {e}")

    except Exception as e:
        print("[-] Client handling error:")
        print(traceback.format_exc())

    finally:
        try:
            conn.close()
        except:
            pass
        print(f"[+] Connection closed: {addr}")


def main():
    parser = argparse.ArgumentParser(description="Stable RSA File Transfer Server")

    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--key", default="private.pem")

    args = parser.parse_args()

    with open(args.key, "rb") as f:
        private_key = RSA.import_key(f.read())

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # allow fast restart
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    server.bind((args.host, args.port))
    server.listen(5)

    print(f"[+] Server running on {args.host}:{args.port}")
    print("[+] Waiting for connections... (CTRL+C to stop)\n")

    try:
        while True:
            try:
                conn, addr = server.accept()
                handle_client(conn, addr, private_key)

            except KeyboardInterrupt:
                print("\n[!] Stopping server (KeyboardInterrupt)")
                break

            except Exception as e:
                print(f"[-] Accept error: {e}")
                continue

    finally:
        try:
            server.close()
        except:
            pass
        print("[+] Server shutdown complete")


if __name__ == "__main__":
    main()
