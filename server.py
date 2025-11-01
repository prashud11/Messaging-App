import socket, threading
from crypto import generate_rsa_keypair, serialize_public_key, rsa_decrypt, aesgcm_encrypt, aesgcm_decrypt
from common import send_blob, recv_blob

HOST = "0.0.0.0"
PORT = 5050

def main():
    print(f"Server listening on {HOST}:{PORT}")
    priv, pub = generate_rsa_keypair()
    with socket.create_server((HOST, PORT), reuse_port=True) as srv:
        conn, addr = srv.accept()
        with conn:
            print("Client connected:", addr)
            # Send public key
            send_blob(conn, serialize_public_key(pub))
            # Receive AES key (encrypted)
            enc_key = recv_blob(conn)
            aes_key = rsa_decrypt(priv, enc_key)
            print("Session key established. You can chat now.")
            # Start chat
            stop = threading.Event()

            def rx():
                while not stop.is_set():
                    data = recv_blob(conn)
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
                    send_blob(conn, aesgcm_encrypt(aes_key, text.encode("utf-8")))
            finally:
                stop.set()
                print("Connection closed.")

if __name__ == "__main__":
    main()
