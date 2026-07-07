#!/usr/bin/env python3
"""A minimal voice-AI WebSocket media server for siphon-rtp's RTP<->WebSocket bridge.

siphon-rtp dials this server when a native-JSON `offer` carries `ws_uri` in its profile. The engine
decodes the caller's RTP to linear PCM and streams it here; PCM we send back is encoded to RTP toward
the caller. We never touch RTP, jitter buffers, or codecs.

The wire (see docs/cookbook/voice-ai.md):
  - text frames: a small JSON control envelope {"type": ..., "data": ...}, camelCase fields.
    The first frame is `start`, announcing the stream id and the audio format.
  - binary frames: one raw little-endian L16 (16-bit mono PCM) frame per ptime. At 8 kHz / 20 ms
    that is 320 bytes. Just send binary frames back to play audio; no announcement is needed.
  - `clear` (server -> ... no, client sends nothing): WE send `clear` to flush queued playout for
    barge-in; the engine replies with a `mark` named "cleared".
  - `stop` (or closing the socket) ends the bridge.

Run:
    pip install websockets
    python3 server.py            # listens on ws://127.0.0.1:9001/stream

Then `offer` a call with profile {"ws_uri": "ws://127.0.0.1:9001/stream"} (see ../b2bua-transcode
for a control driver, or docs/cookbook/voice-ai.md). This example echoes the caller back to prove
the path end to end; the `handle_audio` hook is where a real agent would run STT -> LLM -> TTS.
"""

import asyncio
import json
import logging

import websockets

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
log = logging.getLogger("voice-ai")


class Session:
    """One bridged call. Replace `handle_audio` with a real STT/TTS agent."""

    def __init__(self, ws):
        self.ws = ws
        self.stream_id = None
        self.sample_rate = 8000
        self.bytes_per_frame = 320  # set from the `start` media format

    def on_start(self, data):
        self.stream_id = data["streamId"]
        media = data["media"]
        self.sample_rate = media["sampleRate"]
        # bytes/frame = sampleRate/1000 * ptime * 2 (16-bit mono)
        self.bytes_per_frame = self.sample_rate // 1000 * media["ptime"] * 2
        log.info("start %s %s", self.stream_id, media)

    async def handle_audio(self, pcm: bytes):
        """Called once per uplink frame with little-endian L16 mono PCM.

        A real agent would buffer this, run speech-to-text, drive an LLM, synthesize speech, and
        send the TTS PCM back as binary frames. Here we simply echo it, which proves the full
        RTP -> decode -> WS -> encode -> RTP round trip (you hear yourself with ~2 frames of delay).
        """
        # Sanity: the engine sends exactly one ptime frame per binary message.
        if len(pcm) != self.bytes_per_frame:
            log.warning("unexpected frame size %d (want %d)", len(pcm), self.bytes_per_frame)
        await self.ws.send(pcm)  # downlink: play it straight back

    async def barge_in(self):
        """Flush anything still queued for playout (e.g. when the caller starts talking over the
        agent). The engine acknowledges with a `mark` named "cleared"."""
        await self.ws.send(json.dumps(
            {"type": "clear", "data": {"streamId": self.stream_id, "reason": "barge_in"}}
        ))


async def serve(ws):
    session = Session(ws)
    try:
        async for message in ws:
            if isinstance(message, (bytes, bytearray)):
                await session.handle_audio(bytes(message))
                continue
            envelope = json.loads(message)
            kind = envelope.get("type")
            if kind == "start":
                session.on_start(envelope["data"])
            elif kind == "mark":
                log.info("mark %s", envelope["data"])          # e.g. our clear was applied
            elif kind == "stop":
                log.info("stop %s", session.stream_id)
                break
            else:
                log.info("control %s %s", kind, envelope.get("data"))
    except websockets.ConnectionClosed:
        pass
    finally:
        log.info("closed %s", session.stream_id)


async def main():
    async with websockets.serve(serve, "127.0.0.1", 9001):
        log.info("listening on ws://127.0.0.1:9001/stream")
        await asyncio.Future()  # run forever


if __name__ == "__main__":
    asyncio.run(main())
