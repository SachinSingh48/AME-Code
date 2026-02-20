import asyncio
import websockets
import json
import sys

# Import your custom encryption classes and hash function
from src.receiver_am import ReceiverAnamorphicEncryption
from src.sender_am import SenderAnamorphicEncryption
from src.utils import sha255_hash

# GLOBAL VARIABLES
peer_key = None 
my_name = ""
mode = "NORMAL" # Default mode

# ANAMORPHIC SETUP
# We need the Sender engine to perform the "hiding" logic (fRandom)
sender_engine = SenderAnamorphicEncryption()

# In a real scenario, this key is exchanged via Diffie-Hellman. 
# For the thesis demo, we verify the logic using a hardcoded shared secret.
SHARED_THESIS_SECRET = b"TOP_SECRET_THESIS_KEY_2024"
sender_engine.set_prf_key(SHARED_THESIS_SECRET)

# --------------------------
# SEND LOOP
# --------------------------
async def send_messages(websocket, rae):
    global peer_key
    global mode
    
    # We use a separate thread for input() so it doesn't block the async loop
    loop = asyncio.get_event_loop()
    
    while True:
        # 1. Get user input
        msg_text = await loop.run_in_executor(None, input)
        
        # --- COMMANDS ---
        if msg_text.strip().upper() == "/COVERT":
            mode = "COVERT"
            print("[System]: 🕵️  Switched to COVERT MODE. Messages will hide a secret '1'.")
            continue
        elif msg_text.strip().upper() == "/NORMAL":
            mode = "NORMAL"
            print("[System]: 🛡️  Switched to NORMAL MODE.")
            continue
        # ----------------
        
        # 2. Check if we have someone to talk to
        if peer_key is None:
            print("[System]: Cannot send yet. Waiting for friend's Public Key...")
            continue

        # 3. Encrypt based on Mode
        ciphertext = None
        
        if mode == "NORMAL":
            # --- STANDARD ELGAMAL ---
            # calculate hash before encryption to verify integrity
            original_hash = sha255_hash(msg_text).hex()
            print(f"[Debug] Pre-Encryption Hash: {original_hash}")
            
            ciphertext = rae.NormalEncrypt(peer_key, msg_text)
            print(f"You (Normal): {msg_text}")
            
        elif mode == "COVERT":
            # --- ANAMORPHIC ENCRYPTION ---
            print("[System]: ⏳ Mining for anamorphic randomness (hiding bit 1)...")
            
            # Convert text to integer (the visible message)
            m_int = rae.pke.text_to_int(msg_text, peer_key['p'])
            
            # The secret payload we are hiding (e.g., bit 1)
            hidden_bit = 1
            
            # Use fRandom to find specific randomness 'y' that embeds the bit
            # Note: We pass None for dPK because we are using the PRF-based method
            ct, y_used = sender_engine.fRandom(peer_key, m_int, None, hidden_bit)
            
            if ct:
                ciphertext = ct
                print(f"You (Covert): {msg_text} [Hidden: 1]")
            else:
                print("[Error]: Failed to generate covert ciphertext. Try again.")
                continue

        # 4. Wrap in JSON Protocol
        payload = {
            "type": "message",
            "sender": my_name,
            "ciphertext": ciphertext
        }
        
        # 5. Send to Server
        await websocket.send(json.dumps(payload))

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
                    # send OUR key back so they can reply.
                    should_reply = False
                    if peer_key is None:
                        should_reply = True
                    
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
                        # 1. VISIBLE DECRYPTION (What the censor sees)
                        decrypted_int = rae.NormalDecryptStandard(aSK, encrypted_data)
                        plaintext = rae.pke.int_to_text(decrypted_int)
                        
                        # Verify Hash
                        received_hash = sha255_hash(plaintext).hex()
                        
                        # 2. COVERT DECRYPTION (What we see)
                        # Check if the ciphertext hides a bit using our Shared Secret
                        hidden_bit = sender_engine.CovertDecryptSender(SHARED_THESIS_SECRET, {'ct': encrypted_data})
                        
                        # 3. DISPLAY
                        print(f"\n[Debug] Hash: {received_hash}")
                        print(f"{sender}: {plaintext}")
                        
                        if hidden_bit == 1:
                            print(f"   [!] 🚨 COVERT MESSAGE DETECTED! Hidden Bit: {hidden_bit}")
                            
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
        print("[Tip]: Type '/covert' to enable Anamorphic Mode, or '/normal' to switch back.")

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