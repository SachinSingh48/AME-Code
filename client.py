import asyncio
import websockets
import json
import sys

# Import your custom encryption classes and hash function
from src.receiver_am import ReceiverAnamorphicEncryption
from src.utils import sha255_hash

# GLOBAL VARIABLES
peer_key = None 
my_name = ""

# --------------------------
# SEND LOOP
# --------------------------
async def send_messages(websocket, rae):
    global peer_key
    
    # We use a separate thread for input() so it doesn't block the async loop
    loop = asyncio.get_event_loop()
    
    while True:
        # 1. Get user input
        msg_text = await loop.run_in_executor(None, input)
        
        # 2. Check if we have someone to talk to
        if peer_key is None:
            print("[System]: Cannot send yet. Waiting for friend's Public Key...")
            continue

        # --- VERIFICATION STEP (SENDER) ---
        # calculate hash before encryption to verify integrity later
        original_hash = sha255_hash(msg_text).hex()
        print(f"[Debug] Original Hash (Pre-Encryption): {original_hash}")
        # ----------------------------------
            
        # 3. Encrypt
        # Use NormalEncryptStandard if you have it, otherwise NormalEncrypt 
        # (Assuming NormalEncrypt returns the dict {'c1':..., 'c2':...})
        ciphertext = rae.NormalEncrypt(peer_key, msg_text)
        
        # 4. Wrap in JSON Protocol
        payload = {
            "type": "message",
            "sender": my_name,
            "ciphertext": ciphertext
        }
        
        # 5. Send to Server
        await websocket.send(json.dumps(payload))
        print(f"You: {msg_text}")

# --------------------------
# RECEIVE LOOP
# --------------------------
async def receive_messages(websocket, rae, aSK, my_public_key):
    global peer_key
    global my_name
    
    while True:
        try:
            data = await websocket.recv()
            packet = json.loads(data)
            sender = packet.get('sender', 'Unknown')

            # --- CASE A: RECEIVED A PUBLIC KEY ---
            if packet['type'] == 'pubkey':
                if sender != my_name:
                    print(f"\n[System]: Received Public Key from {sender}.")
                    
                    # LOGIC: If this is the first time we are seeing a key, 
                    # or if we are just connecting, we should share OUR key back 
                    # to ensure they can talk to us.
                    should_reply = False
                    if peer_key is None:
                        should_reply = True
                    
                    # Store the key
                    peer_key = packet['key']
                    
                    if should_reply:
                        print(f"[System]: sending my key back to {sender}...")
                        pub_payload = {
                            "type": "pubkey",
                            "sender": my_name,
                            "key": my_public_key 
                        }
                        await websocket.send(json.dumps(pub_payload))

            # --- CASE B: RECEIVED A MESSAGE ---
            elif packet['type'] == 'message':
                if sender != my_name:
                    encrypted_data = packet['ciphertext']
                    
                    try:
                        decrypted_int = rae.NormalDecryptStandard(aSK, encrypted_data)
                        plaintext = rae.pke.int_to_text(decrypted_int)
                        
                        # Verify Hash
                        received_hash = sha255_hash(plaintext).hex()
                        print(f"\n[Debug] Decrypted Hash: {received_hash}")
                        
                        print(f"{sender}: {plaintext}")
                    except Exception as e:
                        print(f"[Error] Decryption failed: {e}")

        except websockets.exceptions.ConnectionClosed:
            print("[System]: Connection closed.")
            break
        except Exception as e:
            print(f"[Error]: {e}")

# --------------------------
# SETUP
# --------------------------
def generate_key():
    rae = ReceiverAnamorphicEncryption()
    
    # Ask for a username
    name = input(f"Enter your username: ")
    print(f"[System]: Generating keys for {name}...")
    
    # aPK contains {'pk0': ..., 'pk1': ..., 'sigma': ...}
    aPK, aSK, dkey = rae.AnamorphicKeyGen(256) # 256 bits
    return name, rae, aPK, aSK

async def main():
    global my_name
    
    # Connect to the local server
    uri = "ws://localhost:8765"
    async with websockets.connect(uri) as websocket:
        
        # 1. Generate Keys locally
        name, rae, aPK, aSK = generate_key()
        my_name = name
        
        # 2. Publish Public Key (Handshake)
        # We only need to share 'pk0' for normal chat
        pub_payload = {
            "type": "pubkey",
            "sender": my_name,
            "key": aPK['pk0'] 
        }
        await websocket.send(json.dumps(pub_payload))
        print("[System]: Connected. Public Key sent. Waiting for friend...")

        # 3. Run Send and Receive loops simultaneously
        await asyncio.gather(
            send_messages(websocket, rae),
            receive_messages(websocket, rae, aSK, aPK['pk0'])
        )

# Run the program
if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[System]: Exiting...")