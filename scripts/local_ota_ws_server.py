#!/usr/bin/env python3
import argparse
import asyncio
import json
import logging
import time
import uuid

from aiohttp import web, WSMsgType


LOGGER = logging.getLogger("local_ota_ws_server")


class LocalServer:
    def __init__(self, ws_url: str, access_token: str):
        self.ws_url = ws_url
        self.access_token = access_token

    async def ota_handler(self, request: web.Request) -> web.Response:
        body = await request.text()
        if body:
            LOGGER.info("OTA request: %s", body)
        response = {
            "websocket": {
                "url": self.ws_url,
                "access_token": self.access_token,
            },
            "server_time": {
                "timestamp": int(time.time() * 1000),
                "timezone_offset": 0,
            },
        }
        return web.json_response(response)

    async def ws_handler(self, request: web.Request) -> web.StreamResponse:
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        auth = request.headers.get("Authorization", "")
        LOGGER.info("WS connected, Authorization=%s", auth)

        session_id = str(uuid.uuid4())

        async for msg in ws:
            if msg.type == WSMsgType.TEXT:
                LOGGER.info("WS text: %s", msg.data)
                try:
                    payload = json.loads(msg.data)
                except json.JSONDecodeError:
                    continue

                msg_type = payload.get("type")
                if msg_type == "hello":
                    await ws.send_json(
                        {
                            "type": "hello",
                            "transport": "websocket",
                            "session_id": session_id,
                            "audio_params": {"sample_rate": 24000, "frame_duration": 60},
                        }
                    )
                elif msg_type == "listen":
                    text = payload.get("text", "收到")
                    await ws.send_json({"type": "stt", "text": text})
                    await ws.send_json({"type": "llm", "emotion": "happy"})
                    await ws.send_json({"type": "tts", "state": "start"})
                    await ws.send_json(
                        {
                            "type": "tts",
                            "state": "sentence_start",
                            "text": "服务已连通，当前是本地测试回复。",
                        }
                    )
                    await ws.send_json({"type": "tts", "state": "stop"})
            elif msg.type == WSMsgType.BINARY:
                LOGGER.info("WS binary len=%d", len(msg.data))
            elif msg.type == WSMsgType.ERROR:
                LOGGER.error("WS error: %s", ws.exception())

        LOGGER.info("WS disconnected")
        return ws


async def start_servers(ota_port: int, ws_port: int, ws_url: str, access_token: str) -> None:
    server = LocalServer(ws_url=ws_url, access_token=access_token)

    ota_app = web.Application()
    ota_app.router.add_get("/xiaozhi/ota/", server.ota_handler)
    ota_app.router.add_post("/xiaozhi/ota/", server.ota_handler)

    ws_app = web.Application()
    ws_app.router.add_get("/xiaozhi/v1/", server.ws_handler)

    ota_runner = web.AppRunner(ota_app)
    ws_runner = web.AppRunner(ws_app)
    await ota_runner.setup()
    await ws_runner.setup()

    ota_site = web.TCPSite(ota_runner, host="0.0.0.0", port=ota_port)
    ws_site = web.TCPSite(ws_runner, host="0.0.0.0", port=ws_port)
    await ota_site.start()
    await ws_site.start()

    LOGGER.info("OTA server listening on http://127.0.0.1:%d/xiaozhi/ota/", ota_port)
    LOGGER.info("WS server listening on ws://127.0.0.1:%d/xiaozhi/v1/", ws_port)

    while True:
        await asyncio.sleep(3600)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Local OTA + WS server")
    parser.add_argument("--ota-port", type=int, default=8780)
    parser.add_argument("--ws-port", type=int, default=8781)
    parser.add_argument("--ws-url", required=True)
    parser.add_argument("--access-token", default="test-token")
    return parser.parse_args()


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    args = parse_args()
    asyncio.run(start_servers(args.ota_port, args.ws_port, args.ws_url, args.access_token))


if __name__ == "__main__":
    main()
