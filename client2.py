import asyncio
import websockets
import json
import base64

from src.receiver_am import ReceiverAnamorphicEncryption

SERVER_URL = "ws://localhost:8765"
rae = ReceiverAnamorphicEncryption()


class E2EClient:
    def __init__(self, client_id, aSK, dkey):
        self.id = client_id
        self.aSK = aSK
        self.dkey = dkey
        self.ws = None

        # Only 1 peer → single pubkey
        self.peer_pubkey = None
        self.pubkey_ready = asyncio.Event()


    async def connect(self):
        """Connect and send HELLO with pubkey."""
        self.ws = await websockets.connect(SERVER_URL)

        hello = {
            "type": "hello",
            "id": self.id,
            "dkey": json_safe(self.dkey),
        }
        await self.ws.send(json.dumps(hello))

        print(f"[CONNECTED] as {self.id}")

        # Start listening in the background
        asyncio.create_task(self.listen())

    async def listen(self):
        """Continuously receive messages."""
        try:
            async for msg in self.ws:
                try:
                    data = json.loads(msg)
                except:
                    print("[RECV] Invalid JSON:", msg)
                    continue

                await self.handle_message(data)
        except websockets.ConnectionClosed:
            print("[DISCONNECTED]")

    async def handle_message(self, msg):
        """Handle incoming server messages."""
        t = msg.get("type")

        if t == "pubkey":
            print(f"[PUBKEY] Received pubkey from {msg['id']}")
            self.peer_pubkey = msg["dkey"]
            self.pubkey_ready.set()

        elif t == "pubkey_not_found":
            print(f"[ERROR] pubkey for {msg['id']} not found")

        elif t == "ciphertext":
            ciphertext = json_restore(msg.get("body"))
            decrypted_m0 = rae.NormalDecrypt(self.aSK, ciphertext)
            plaintext_m0 = rae.pke.int_to_text(decrypted_m0)
            decrypted_m1 = rae.DoubleDecrypt(self.dkey, ciphertext)
            plaintext_m1 = rae.pke.int_to_text(decrypted_m1)

            print(f"[MSG] From {msg['from']}: {plaintext_m0}")
            print(f"[SECRET] From {msg['from']}: {plaintext_m1}")

            
            # if self.peer_pubkey == None:
            #     continue_chat = input(f"Wanna continue conversation with {msg.get("from")} yes/no? ")
            #     if continue_chat == "yes":
            #         asyncio.create_task(self.request_pubkey(msg.get("from")))

            # m0 = input("You: ")
            # m1 = input("Secret: ")
            # asyncio.create_task(self.send_ciphertext(msg.get("from"), m0, m1))
            
        else:
            print("[UNKNOWN]", msg)

    async def request_pubkey(self, target_id):
        """Ask server for someone’s pubkey."""
        req = {
            "type": "get_pubkey",
            "id": target_id
        }
        await self.ws.send(json.dumps(req))

    async def send_ciphertext(self, target_id, m0, m1 , nonce="0"):
        """Send encrypted data to another peer."""

        ciphertext = rae.AnamorphicEncrypt(json_restore(self.peer_pubkey), m0, m1)
        msg = {
            "type": "ciphertext",
            "to": target_id,
            "from": self.id,
            "nonce": nonce,
            "body": json_safe(ciphertext)
        }
        await self.ws.send(json.dumps(msg))

    async def close(self):
        """Close the connection."""
        if self.ws:
            await self.ws.close()
            print("[CLOSED]")


def generate_key():
    
    # Ask for a username
    name = input(f"Enter your username: ")
    print(f"[System]: Generating keys for {name}...")
    
    # aPK contains {'pk0': ..., 'pk1': ..., 'sigma': ...}
    _, aSK, dkey = rae.AnamorphicKeyGen(256) # 256 bits
    return name, aSK, dkey

def json_safe(obj):
    if isinstance(obj, dict):
        return {k: json_safe(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [json_safe(v) for v in obj]
    elif isinstance(obj, (bytes, bytearray)):
        return base64.b64encode(obj).decode()
    else:
        return obj
    
import base64

def json_restore(obj):
    # If it's a dict, restore each element
    if isinstance(obj, dict):
        return {k: json_restore(v) for k, v in obj.items()}

    # Restore lists
    if isinstance(obj, list):
        return [json_restore(v) for v in obj]

    # Detect base64-encoded bytes
    if isinstance(obj, str):
        try:
            data = base64.b64decode(obj)
            return data
        except Exception:
            return obj

    # primitives (int, float, None, bool)
    return obj

async def main():    
        
    # 1. Generate Keys locally
    my_name, aSK, dkey = generate_key()
    
    # 2. Publish Public Key        
    your_client = E2EClient(my_name, aSK ,dkey)
    await your_client.connect()

    receiver = input("Enter to skip or start a chat with? ")
    
    if receiver != "":
        await your_client.request_pubkey(receiver)
        # make sure you receive pubkey of peer
        await your_client.pubkey_ready.wait()
        m0 = input("You: ")
        m1 = input("Secret: ")
        await your_client.send_ciphertext(receiver, m0, m1)
    
    while True:
        await asyncio.sleep(5)

# Run the program
if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[System]: Exiting...")