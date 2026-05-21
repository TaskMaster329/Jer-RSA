import socket
import argparse
import traceback
from tqdm import tqdm
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


def decrypt_data_stream(conn, private_key, total_size):
    cipher = PKCS1_OAEP.new(private_key)
    key_size = private_key.size_in_bytes()

    decrypted = b""
    received = 0

    with tqdm(
        total=total_size,
        unit="B",
        unit_scale=True,
        desc="Receiving"
    ) as progress:

        while True:
            try:
                chunk = conn.recv(key_size)

                if not chunk:
                    break

                received += len(chunk)
                progress.update(len(chunk))

                try:
                    decrypted += cipher.decrypt(chunk)

                except Exception as e:
                    print(f"\n[-] Decryption block failed: {e}")
                    continue

            except Exception as e:
                print(f"\n[-] Receive error: {e}")
                break

    return decrypted


def handle_client(conn, addr, private_key):
    print(f"\n[+] New connection from {addr[0]}:{addr[1]}")

    try:
        # ---- receive filename length ----
        name_len_bytes = conn.recv(2)

        if len(name_len_bytes) < 2:
            print("[-] Invalid filename header")
            return

        # ---- receive filename ----
        name_len = int.from_bytes(name_len_bytes, "big")
        file_name = conn.recv(name_len).decode(errors="ignore")

        print(f"[+] Receiving file: {file_name}")

        # ---- receive encrypted payload size ----
        size_bytes = conn.recv(8)

        if len(size_bytes) < 8:
            print("[-] Invalid file size header")
            return

        total_size = int.from_bytes(size_bytes, "big")

        print(f"[+] Encrypted payload size: {total_size} bytes")

        # ---- decrypt stream ----
        decrypted = decrypt_data_stream(
            conn,
            private_key,
            total_size
        )

        if not decrypted:
            print("[-] No decrypted data received")
            return

        # ---- save file ----
        try:
            with open(file_name, "wb") as f:
                f.write(decrypted)

            print(f"[+] File successfully saved: {file_name}")
            print(f"[+] File size: {len(decrypted)} bytes")

        except Exception as e:
            print(f"[-] File write error: {e}")

    except Exception:
        print("[-] Client handling error:")
        print(traceback.format_exc())

    finally:
        try:
            conn.close()

        except:
            pass

        print(f"[+] Connection closed: {addr[0]}:{addr[1]}")


def load_private_key(path):
    try:
        with open(path, "rb") as f:
            return RSA.import_key(f.read())

    except FileNotFoundError:
        print(f"[-] Private key not found: {path}")
        exit(1)

    except Exception as e:
        print(f"[-] Failed to load private key: {e}")
        exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Stable RSA File Transfer Server"
    )

    parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="Server bind address (default: 0.0.0.0)"
    )

    parser.add_argument(
        "--port",
        type=int,
        default=9000,
        help="Server listening port (default: 9000)"
    )

    parser.add_argument(
        "--key",
        default="private.pem",
        help="Private RSA key file (default: private.pem)"
    )

    args = parser.parse_args()

    private_key = load_private_key(args.key)

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # allow fast restart
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server.bind((args.host, args.port))

    except OSError as e:
        if e.errno == 98:
            print(f"[-] Port {args.port} is already in use")
            print("[!] Stop the existing process or use another port")
            return

        print(f"[-] Bind failed: {e}")
        return

    except Exception as e:
        print(f"[-] Socket bind error: {e}")
        return

    server.listen(5)

    print(f"[+] Server running on {args.host}:{args.port}")
    print("[+] Waiting for connections... (CTRL+C to stop)\n")

    try:
        while True:
            try:
                conn, addr = server.accept()
                handle_client(conn, addr, private_key)

            except KeyboardInterrupt:
                print("\n[!] Server stopped by user")
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
