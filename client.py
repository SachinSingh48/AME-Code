import asyncio
import json
import websockets
from src.receiver_am import ReceiverAnamorphicEncryption
from src.sender_am import SenderAnamorphicEncryption
from src.base_pke import ElGamalPKE
from src.utils import get_random_int, sha255_hash

LAMBDA_BITS = 256

async def send_messages(websocket):
    loop = asyncio.get_event_loop()
    while True:
        msg = await loop.run_in_executor(None, input)
        print("You:", msg)
        await websocket.send(msg)

async def receive_messages(websocket):
    while True:
        msg = await websocket.recv()
        print("Friend:", msg)

def generate_key():
    rae = ReceiverAnamorphicEncryption()
    name = input(f"\nRegister name: ")
    print(f"[System]: Generating anamorphic keys for user {name}")
    aPK, aSK, dkey = rae.AnamorphicKeyGen(LAMBDA_BITS)
    return [name, aPK, aSK, dkey]

async def main():
    async with websockets.connect("ws://localhost:8765") as websocket:
        name, aPK, aSK, dkey = generate_key()
        pub_keys = [name, aPK, dkey]
        print("[System]: Anamorphic keys generated and published.")
        await websocket.send(json.dumps(pub_keys))

        await asyncio.gather(
            send_messages(websocket),
            receive_messages(websocket)
        )

asyncio.run(main())
