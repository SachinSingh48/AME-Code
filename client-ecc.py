import asyncio
import websockets
import json
import base64
import numpy as np
import os
from src.receiver_am import ReceiverAnamorphicEncryption

SERVER_URL = "ws://localhost:8765"
rae = ReceiverAnamorphicEncryption()

# --- JSON SERIALIZATION FOR NUMPY ---
def json_safe(obj):
    if isinstance(obj, np.ndarray):
        return {"__numpy__": obj.tolist()}
    elif isinstance(obj, np.integer): 
        return int(obj)
    elif isinstance(obj, (list, tuple)):
        return [json_safe(v) for v in obj]
    elif isinstance(obj, dict):
        return {k: json_safe(v) for k, v in obj.items()}
    elif isinstance(obj, (bytes, bytearray)):
        return {"__bytes__": base64.b64encode(obj).decode()}
    return obj

def json_restore(obj):
    if isinstance(obj, dict):
        if "__numpy__" in obj:
            return np.array(obj["__numpy__"])
        if "__bytes__" in obj:
            return base64.b64decode(obj["__bytes__"])
        return {k: json_restore(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [json_restore(v) for v in obj]
    return obj

# --- KEY MANAGEMENT ---
def save_keys(username, aSk, dkey):
    """Saves the generated keys to a local JSON file."""
    data = {
        "aSk": json_safe(aSk),
        "dkey": json_safe(dkey)
    }
    with open(f"{username}_keys.json", "w") as f:
        json.dump(data, f)
    print(f"[System] Keys securely saved to {username}_keys.json")

def load_keys(username):
    """Loads keys from a local JSON file if it exists."""
    filename = f"{username}_keys.json"
    if not os.path.exists(filename):
        return None
    
    print(f"[System] Found existing keys! Loading from {filename}...")
    with open(filename, "r") as f:
        data = json.load(f)
    
    data = json_restore(data)
    return data["aSk"], data["dkey"]

# --- CLIENT LOGIC ---
class E2EClient:
    def __init__(self, client_id, aSK, dkey):
        self.id = client_id
        self.aSK = aSK
        self.dkey = dkey
        self.ws = None

        self.peer_pubkey = None
        self.pubkey_ready = asyncio.Event()
        
        self.active_peer = None
        self.msg_backlog = []

    async def connect(self):
        """Connect and send HELLO with pubkey."""
        self.ws = await websockets.connect(SERVER_URL)
        hello = {
            "type": "hello",
            "id": self.id,
            "dkey": json_safe(self.dkey),
        }
        await self.ws.send(json.dumps(hello))
        print(f"[CONNECTED] Logged in as: {self.id}")

        # Start listening in the background
        asyncio.create_task(self.listen())

    async def listen(self):
        """Continuously receive messages."""
        try:
            async for msg in self.ws:
                try:
                    data = json.loads(msg)
                except Exception:
                    continue
                await self.handle_message(data)
        except websockets.ConnectionClosed:
            print("\n[DISCONNECTED] Server closed the connection.")
            self.pubkey_ready.set()

    async def handle_message(self, msg):
        """Handle incoming server messages."""
        t = msg.get("type")

        if t == "pubkey":
            self.peer_pubkey = json_restore(msg["dkey"])
            self.pubkey_ready.set()

        elif t == "pubkey_not_found":
            self.pubkey_ready.set()
            print(f"[ERROR] pubkey for {msg['id']} not found")

        elif t == "peer_left":
            if self.active_peer and msg['from'] == self.active_peer:
                print(f"\n\n[SYSTEM] User '{msg['from']}' has left the chat.")
                self.peer_pubkey = None
                print("(Press Enter to continue...)")

        elif t == "ciphertext":
            sender = msg['from']
            
            # --- FILTERING LOGIC ---
            # If we are NOT actively chatting with this person, buffer the message
            if self.active_peer != sender:
                self.msg_backlog.append(msg)
                print(f"\n[🔔] New message from '{sender}'.")
                return

            # If we ARE chatting with them, print it immediately
            self.print_chat_message(msg)

    def print_chat_message(self, msg):
        """Decodes and prints a message to the UI."""
        ciphertexts = json_restore(msg.get("body"))

        decrypted_m0 = rae.NormalDecrypt(self.aSK, ciphertexts)
        public_msg = rae.pke.int_to_text(decrypted_m0)
        decrypted_m1 = rae.DoubleDecrypt(self.dkey, ciphertexts)
        secret_msg = rae.pke.int_to_text(decrypted_m1)

        sender = msg['from']

        print(f"\n\r💬 {sender} (Public): {public_msg}")
        if public_msg != secret_msg:
            print(f"\r🤫 {sender} (Secret): {secret_msg}")

    def set_active_peer(self, peer_id):
        """Sets the target peer and flushes relevant backlog messages."""
        self.active_peer = peer_id
        
        if peer_id is None:
            return
        
        if self.msg_backlog:
            relevant_msgs = [m for m in self.msg_backlog if m['from'] == peer_id]
            if relevant_msgs:
                print(f"\n[SYSTEM] Retrieving {len(relevant_msgs)} hidden messages from {peer_id}...")
                for msg in relevant_msgs:
                    self.print_chat_message(msg)
            
            # Keep only the messages from other people in the backlog
            self.msg_backlog = [m for m in self.msg_backlog if m['from'] != peer_id]

    async def request_pubkey(self, target_id):
        """Ask server for someone’s pubkey."""
        self.pubkey_ready.clear()
        req = {
            "type": "get_pubkey",
            "id": target_id
            }
        if self.ws:
            try:
                await self.ws.send(json.dumps(req))
            except Exception:
                pass

    async def send_ciphertext(self, target_id, m0, m1):
        if not self.peer_pubkey:
            print(f"\n[ERROR] Cannot send. Public key missing.")
            return

        ciphertexts = rae.AnamorphicEncrypt(json_restore(self.peer_pubkey), m0, m1)

        msg = {
            "type": "ciphertext",
            "to": target_id,
            "from": self.id,
            "body": json_safe(ciphertexts)
        }
        
        if self.ws:
            try:
                await self.ws.send(json.dumps(msg))
            except websockets.ConnectionClosed:
                print("[ERROR] Connection to server lost.")

    async def send_peer_left(self, target_id):
        msg = {"type": "peer_left", "to": target_id, "from": self.id}
        if self.ws:
            try:
                await self.ws.send(json.dumps(msg))
            except:
                pass 

    async def close(self):
        if self.ws:
            try:
                await self.ws.close()
                print("[System] Connection closed cleanly.")
            except:
                pass

async def main():    
    print("========================================")
    print("      ANAMORPHIC CHAT        ")
    print("========================================")
    
    my_name = input("Enter your username: ")
    
    # --- SMART KEY LOADING ---
    keys = load_keys(my_name)
    if keys:
        aSk, dkey = keys
    else:
        print("[System] Generating NEW keys... (This may take a few seconds)")
        _, aSk, dkey = rae.AnamorphicKeyGen(2048) # key length
        save_keys(my_name, aSk, dkey)
    # -------------------------

    your_client = E2EClient(my_name, aSk, dkey)
    await your_client.connect()

    # --- OUTER LOOP: MAIN MENU ---
    while True:
        your_client.set_active_peer(None)
        
        receiver = await asyncio.to_thread(input, "\n[Menu] Who do you want to chat with? (Type name, or /quit): ")
        receiver = receiver.strip()
        
        if receiver == "/quit":
            await your_client.close()
            break
            
        if receiver == "":
            continue 
            
        # Entering a chat!
        your_client.set_active_peer(receiver)
        
        await your_client.request_pubkey(receiver)
        await your_client.pubkey_ready.wait()
        
        if not your_client.peer_pubkey:
            print(f"\n[System] '{receiver}' hasn't joined the server yet.")        
            continue

        print(f"\n[System] Ready to chat with {receiver}!")
        print("Type your messages below. Type '/back' to switch users, or '/quit' to exit.")
        
        # --- INNER LOOP: CHAT SESSION ---
        while True:
            m0 = await asyncio.to_thread(input, f"\n[To: {receiver}] Fake Message: ")
            
            if m0.strip() == "/quit":
                print("\n[System] Exiting application...")
                await your_client.send_peer_left(receiver)
                await your_client.close()
                return 
                
            if m0.strip() == "/back":
                print(f"\n[System] Returning to main menu...")
                await your_client.send_peer_left(receiver)
                break
                
            m1 = await asyncio.to_thread(input, f"[To: {receiver}] Real/Secret Message: ")
            
            if m1.strip() == "/quit":
                print("\n[System] Exiting application...")
                await your_client.send_peer_left(receiver)
                await your_client.close()
                return
                
            if m1.strip() == "/back":
                print(f"\n[System] Returning to main menu...")
                await your_client.send_peer_left(receiver)
                break

            if not your_client.peer_pubkey:
                print(f"[ERROR] Cannot send. '{receiver}' is no longer in the chat.")
                break

            print("[System] Encrypting and sending...")
            await your_client.send_ciphertext(receiver, m0, m1)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[System] Force quitting...")