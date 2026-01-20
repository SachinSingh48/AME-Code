import asyncio
import websockets

# create empty storage for clients {"ws": websocket, "pubkey": list}
clients = set()

# define a function to handle incoming messages from clients
async def handle_message(websocket):
    clients.add(websocket)
    try:
        async for message in websocket:
            for client in clients:
                if client != websocket:
                    await client.send(message)
    finally:
        clients.remove(websocket)

# start the websocket server
async def start_server():
    async with websockets.serve(handle_message, "localhost", 8765):
        print("Chat server running...")
        await asyncio.Future()

# run the server
asyncio.run(start_server())