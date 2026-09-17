from fastapi import WebSocket, WebSocketDisconnect, APIRouter
from typing import List, Dict, Any
import json
import asyncio

router = APIRouter()

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        print(f"[WebSocket] Client connected. Total: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        print(f"[WebSocket] Client disconnected. Total: {len(self.active_connections)}")

    async def broadcast(self, message: Dict[str, Any]):
        if not self.active_connections:
            return

        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except:
                disconnected.append(connection)

        for conn in disconnected:
            self.disconnect(conn)

manager = ConnectionManager()

# Broadcast helper functions
async def broadcast_new_event(event_data: dict):
    await manager.broadcast({"type": "new_event", "data": event_data})

async def broadcast_new_alert(alert_data: dict):
    await manager.broadcast({"type": "new_alert", "data": alert_data})

async def broadcast_new_incident(incident_data: dict):
    await manager.broadcast({"type": "new_incident", "data": incident_data})

async def broadcast_incident_update(incident_data: dict):
    await manager.broadcast({"type": "incident_update", "data": incident_data})

# ===== WEBSOCKET ENDPOINT =====
@router.websocket("/events")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        # Send initial connection confirmation
        await websocket.send_json({
            "type": "connected",
            "status": "ok",
            "message": "Connected to MiniSOC ThreatLens WebSocket"
        })

        # Send a ping every 30 seconds to keep connection alive
        ping_task = asyncio.create_task(send_ping(websocket))

        while True:
            try:
                # Wait for messages with timeout
                data = await asyncio.wait_for(websocket.receive_text(), timeout=60.0)
                if data == "ping":
                    await websocket.send_json({"type": "pong"})
                elif data == "close":
                    await websocket.close()
                    break
            except asyncio.TimeoutError:
                # Send a ping to check if connection is still alive
                try:
                    await websocket.send_json({"type": "ping"})
                except:
                    break
            except WebSocketDisconnect:
                break
            except Exception as e:
                print(f"[WebSocket] Error: {e}")
                break

    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        print(f"[WebSocket] Unexpected error: {e}")
        manager.disconnect(websocket)
    finally:
        ping_task.cancel()
        manager.disconnect(websocket)

async def send_ping(websocket: WebSocket):
    """Send periodic ping to keep connection alive."""
    while True:
        try:
            await asyncio.sleep(30)  # Send ping every 30 seconds
            await websocket.send_json({"type": "ping"})
        except:
            break