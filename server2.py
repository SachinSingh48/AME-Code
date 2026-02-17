import asyncio
import websockets
import json

# Store clients: { "client_id": { "ws": websocket, "pubkey": "..."} }
clients = {}

async def handle_client(ws):
    client_id = None

    try:
        # ---- Expect HELLO message with id + pubkey ----
        hello_raw = await ws.recv()

        try:
            hello = json.loads(hello_raw)
        except:
            await ws.send(json.dumps({"error": "invalid_json"}))
            return

        if hello.get("type") != "hello" or "id" not in hello or "dkey" not in hello:
            await ws.send(json.dumps({"error": "bad_hello"}))
            return

        client_id = hello["id"]
        clients[client_id] = {
            "ws": ws,
            "dkey": hello["dkey"]
        }

        print(f"[JOIN] {client_id}")

        # ---- Main loop: handle client messages ----
        async for raw in ws:
            try:
                msg = json.loads(raw)
            except:
                continue

            # ---- 1. Client requests another client's public key ----
            if msg.get("type") == "get_pubkey":
                target = msg.get("id")
                if target in clients:
                    await ws.send(json.dumps({
                        "type": "pubkey",
                        "id": target,
                        "dkey": clients[target]["dkey"]
                    }))
                else:
                    await ws.send(json.dumps({
                        "type": "pubkey_not_found",
                        "id": target
                    }))

            # ---- 2. Client sends encrypted message to specific peer ----
            elif msg.get("type") == "ciphertext":
                target = msg.get("to")
                if target in clients:
                    try:
                        await clients[target]["ws"].send(raw)
                    except:
                        pass

    finally:
        # Cleanup on disconnect
        if client_id and client_id in clients:
            print(f"[LEAVE] {client_id}")
            clients.pop(client_id, None)


async def main():
    print("Minimal E2E server running on ws://localhost:8765")
    async with websockets.serve(handle_client, "localhost", 8765):
        await asyncio.Future()

asyncio.run(main())