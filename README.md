# Secure Messaging

Simple two-party chat with RSA handshake and AES-GCM transport encryption.

## How to run
1. `python -m venv .venv && source .venv/bin/activate`
2. `pip install -r requirements.txt`
3. In one terminal on the host machine: `python server.py`
4. In another terminal (could be a second machine): `python client.py <server_ip> 5050`

## Notes
- The server generates an RSA keypair at start and sends its public key to the client.
- The client creates a random 256-bit AES key, encrypts it under the server public key, and sends it.
- All chat messages are then encrypted with AES-GCM.
- This is a learning project. For production, add authentication and certificate validation.
