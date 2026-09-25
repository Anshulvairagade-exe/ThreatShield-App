"""Live SOC stream — event arrival, detections, incidents, risk, response."""
import asyncio

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.ws import bus

router = APIRouter()


@router.websocket("/ws/events")
async def event_stream(websocket: WebSocket):
    await websocket.accept()
    await websocket.send_json({"type": "connected", "ts": "", "payload": {}})
    try:
        while True:
            for message in bus.drain(limit=50):
                await websocket.send_json(message)
            await asyncio.sleep(0.2)
    except WebSocketDisconnect:
        pass
