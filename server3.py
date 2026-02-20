import asyncio
import websockets
import json

# Permanent database (in-memory): { "sachin": { "dkey": "...", "queue": [...] } }
users_db = {}
# Active connections: { "sachin": websocket }
active_ws = {}

async def handle_client(ws):
    client_id = None

    try:
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
        
        # 1. Register or update the user in the permanent database
        if client_id not in users_db:
            users_db[client_id] = {"dkey": hello["dkey"], "queue": []}
        else:
            users_db[client_id]["dkey"] = hello["dkey"] # Update key if they restarted
            
        active_ws[client_id] = ws
        print(f"[JOIN] {client_id} connected.")
        
        # NOTE: We no longer dump the queue here! We wait until they pick a chat partner.

        # ---- Main loop: handle client messages ----
        async for raw in ws:
            try:
                msg = json.loads(raw)
            except:
                continue

            # ---- Client requests a public key ----
            if msg.get("type") == "get_pubkey":
                target = msg.get("id")
                
                if target in users_db:
                    # 1. Send the public key
                    await ws.send(json.dumps({
                        "type": "pubkey",
                        "id": target,
                        "dkey": users_db[target]["dkey"]
                    }))
                    
                    # 2. TARGETED INBOX DELIVERY
                    # Only deliver queued messages sent by the 'target'
                    my_queue = users_db[client_id]["queue"]
                    remaining_queue = []
                    
                    delivered_count = 0
                    for q_raw in my_queue:
                        try:
                            q_msg = json.loads(q_raw)
                            if q_msg.get("from") == target:
                                await ws.send(q_raw)
                                delivered_count += 1
                            else:
                                remaining_queue.append(q_raw)
                        except:
                            pass
                            
                    users_db[client_id]["queue"] = remaining_queue
                    if delivered_count > 0:
                        print(f"[SYSTEM] Delivered {delivered_count} queued messages from {target} to {client_id}")
                        
                else:
                    await ws.send(json.dumps({
                        "type": "pubkey_not_found",
                        "id": target
                    }))

            # ---- Route messages to specific peer ----
            elif msg.get("type") in ["ciphertext", "peer_left"]:
                target = msg.get("to")
                
                # If they are actively connected, send it live
                if target in active_ws:
                    try:
                        await active_ws[target].send(raw)
                    except:
                        # Connection broke mid-send, push to queue
                        users_db[target]["queue"].append(raw)
                        active_ws.pop(target, None)
                        
                # If they are offline but registered, queue the message
                elif target in users_db:
                    users_db[target]["queue"].append(raw)

    finally:
        # Cleanup active connection, but LEAVE them in users_db
        if client_id and client_id in active_ws:
            print(f"[LEAVE] {client_id} went offline.")
            active_ws.pop(client_id, None)

async def main():
    print("Advanced E2E Queuing Server running on ws://localhost:8765")
    async with websockets.serve(handle_client, "localhost", 8765):
        await asyncio.Future()

if __name__ == "__main__":
    asyncio.run(main())