#!/usr/bin/env python3
"""Drive siphon-rtp as a B2BUA would, to set up a transcoding call: VoLTE (AMR-WB) <-> PSTN (G.711).

This is the media-plane half of what a back-to-back user agent (SIPhon, or any controller speaking
the native JSON-over-TCP protocol) does. On an inbound INVITE it `offer`s the caller's SDP to the
engine and sends the rewritten SDP toward the callee; on the callee's 200 OK it `answer`s and sends
the rewritten SDP back to the caller. The engine anchors both legs and transcodes between them.

Here leg A is a VoLTE UE offering AMR-WB; leg B is a PSTN gateway that only speaks G.711 A-law. We
ask the engine to present PCMA toward B (`codec-transcode-PCMA`); because A's primary codec (AMR-WB)
then differs from B's (PCMA), the engine engages the transcoder at `answer` time, decoding AMR-WB one
way and A-law the other, per direction.

AMR is a build feature, so start a daemon built with it, then run this script:
    cargo run -p siphon-rtp --features amr -- --control 127.0.0.1:8080   # (or: cargo install siphon-rtp --features amr)
    python3 driver.py

The framing is a 4-byte big-endian length prefix followed by a JSON body (see
docs/control/json.md). This script speaks it directly with the standard library, no dependencies.
"""

import json
import socket
import struct
import sys

CONTROL = ("127.0.0.1", 8080)
CALL_ID = "volte-pstn-demo@198.51.100.20"

# Leg A: a VoLTE UE offering AMR-WB (dynamic PT 96) + RFC 4733 DTMF.
A_OFFER_SDP = (
    "v=0\r\n"
    "o=- 1 1 IN IP4 198.51.100.20\r\n"
    "s=-\r\n"
    "c=IN IP4 198.51.100.20\r\n"
    "t=0 0\r\n"
    "m=audio 5004 RTP/AVP 96 101\r\n"
    "a=rtpmap:96 AMR-WB/16000\r\n"
    "a=fmtp:96 octet-align=1\r\n"
    "a=rtpmap:101 telephone-event/8000\r\n"
    "a=ptime:20\r\n"
)

# Leg B: the PSTN gateway answering with G.711 A-law (PT 8).
B_ANSWER_SDP = (
    "v=0\r\n"
    "o=- 2 2 IN IP4 203.0.113.7\r\n"
    "s=-\r\n"
    "c=IN IP4 203.0.113.7\r\n"
    "t=0 0\r\n"
    "m=audio 8000 RTP/AVP 8 101\r\n"
    "a=rtpmap:8 PCMA/8000\r\n"
    "a=rtpmap:101 telephone-event/8000\r\n"
    "a=ptime:20\r\n"
)


class Control:
    """A tiny native-JSON control client: 4-byte BE length prefix + JSON body."""

    def __init__(self, address):
        self.sock = socket.create_connection(address)
        self.next_id = 0

    def request(self, command, **fields):
        self.next_id += 1
        request_id = self.next_id
        self._send({"id": request_id, "command": command, **fields})
        while True:  # skip any async events (no matching id) until our reply lands
            reply = self._recv()
            if reply.get("id") == request_id:
                if reply.get("result") == "error":
                    raise RuntimeError(f"{command} failed: {reply.get('reason')}")
                return reply

    def _send(self, obj):
        body = json.dumps(obj).encode()
        self.sock.sendall(struct.pack(">I", len(body)) + body)

    def _recv(self):
        length = struct.unpack(">I", self._recv_exact(4))[0]
        return json.loads(self._recv_exact(length))

    def _recv_exact(self, count):
        chunks = b""
        while len(chunks) < count:
            piece = self.sock.recv(count - len(chunks))
            if not piece:
                raise ConnectionError("control connection closed")
            chunks += piece
        return chunks

    def close(self):
        self.sock.close()


def main():
    control = Control(CONTROL)
    try:
        # 1. Inbound INVITE from A: offer A's SDP, ask the engine to transcode toward B as PCMA.
        offer = control.request(
            "offer",
            call_id=CALL_ID,
            from_tag="a-volte",
            sdp=A_OFFER_SDP,
            profile={"flags": ["codec-transcode-PCMA"]},
        )
        print("== rewritten SDP to send toward B (should advertise PCMA) ==")
        print(offer["sdp"])

        # 2. B answers 200 OK with PCMA: answer B's SDP, get the SDP to send back to A.
        answer = control.request(
            "answer",
            call_id=CALL_ID,
            from_tag="a-volte",
            to_tag="b-pstn",
            sdp=B_ANSWER_SDP,
            profile={},
        )
        print("== rewritten SDP to send back to A (should advertise AMR-WB) ==")
        print(answer["sdp"])

        # 3. Media now flows: A<->engine in AMR-WB, engine<->B in PCMA, transcoded per direction.
        #    Point real RTP at the engine's answered ports to hear it. Check the counters:
        stats = control.request("query", call_id=CALL_ID, from_tag="a-volte")
        print("== query ==", stats.get("stats"))

        input("call is up; press Enter to tear it down... ")
    finally:
        control.request("delete", call_id=CALL_ID, from_tag="a-volte")
        control.close()


if __name__ == "__main__":
    try:
        main()
    except (ConnectionRefusedError, RuntimeError) as error:
        sys.exit(f"error: {error} (is siphon-rtp running with --control 127.0.0.1:8080 and --features amr?)")
