import socket
from crypto import load_public_key, rsa_encrypt, generate_aes_key, aesgcm_encrypt, aesgcm_decrypt
from common import send_blob, recv_blob
import threading, sys

def main():
    if len(sys.argv) < 3:
        print("Usage: python client.py <server_ip> <port>")
        return
    host = sys.argv[1]
    port = int(sys.argv[2])

    with socket.create_connection((host, port)) as sock:
        # Receive server public key
        pub_pem = recv_blob(sock)
        pub = load_public_key(pub_pem)

        # Create AES session key and send encrypted under RSA
        aes_key = generate_aes_key()
        enc = rsa_encrypt(pub, aes_key)
        send_blob(sock, enc)
        print("Session key established. You can chat now. Type 'exit' to quit.")

        stop = threading.Event()

        def rx():
            while not stop.is_set():
                data = recv_blob(sock)
                if not data:
                    stop.set(); break
                msg = aesgcm_decrypt(aes_key, data).decode("utf-8", "ignore")
                print(f"\nPeer: {msg}")
        t = threading.Thread(target=rx, daemon=True); t.start()

        try:
            while not stop.is_set():
                text = input("> ")
                if not text:
                    continue
                if text.lower() in ("quit", "exit"):
                    stop.set(); break
                send_blob(sock, aesgcm_encrypt(aes_key, text.encode("utf-8")))
        finally:
            stop.set()
            print("Connection closed.")

if __name__ == "__main__":
    main()
