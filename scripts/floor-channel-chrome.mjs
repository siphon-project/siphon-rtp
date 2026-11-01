// Drives the MCPTT floor data channel with a real browser (headless Chrome) against the engine, in
// both directions: the browser calls the room (forward_join) and the room calls the browser
// (forward_offer with a UDP/TLS/RTP/SAVPF profile, then forward_answer).
// Dependency free: Node's built-in WebSocket speaks the DevTools protocol, node:net the engine's
// length-prefixed JSON control protocol, node:dgram plays a plain RTP listener seat.
//
// Environment: ENGINE_BIN (the siphon-rtp binary), CHROME_BIN, TIMEOUT_MS (default 90000).

import { spawn } from "node:child_process";
import dgram from "node:dgram";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";

const ROOM_PREFIX = "chrome-room";
const BROWSER_TAG = "browser";
const LISTENER_TAG = "listener";
const TIMEOUT_MS = Number(process.env.TIMEOUT_MS ?? 90000);

// TS 24.380 Floor Request as an RTCP APP packet (RFC 3550 6.7): SSRC 0x11223344, name MCPT, subtype 0.
const FLOOR_REQUEST = [0x80, 0xcc, 0x00, 0x03, 0x11, 0x22, 0x33, 0x44, 0x4d, 0x43, 0x50, 0x54, 0x00, 0x02, 0x05, 0x00];
const FLOOR_GRANTED_PAYLOAD = [0x01, 0x02, 0x00, 0x1e, 0x0e, 0x06, 0x12, 0x34, 0x56, 0x78, 0x00, 0x00];
const GRANT_SSRC = 0x55667788;
const GRANT_SUBTYPE = 17;
// The same packet with the subtype in the first octet (V=2, P=0, subtype), length 5 words.
const FLOOR_GRANTED = [0x80 | GRANT_SUBTYPE, 0xcc, 0x00, 0x05, 0x55, 0x66, 0x77, 0x88, 0x4d, 0x43, 0x50, 0x54, ...FLOOR_GRANTED_PAYLOAD];

const hex = (bytes) => Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join(" ");
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

let failures = 0;
function pass(name, detail = "") {
  console.log(`PASS ${name}${detail ? ` (${detail})` : ""}`);
}
function fail(name, detail = "") {
  failures += 1;
  console.log(`FAIL ${name}${detail ? ` (${detail})` : ""}`);
}

const cleanups = [];
let cleaned = false;
function cleanup() {
  if (cleaned) return;
  cleaned = true;
  for (const run of cleanups.reverse()) {
    try {
      run();
    } catch {
      // Best effort: the process is going away.
    }
  }
}
process.on("exit", cleanup);
for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) {
  process.on(signal, () => {
    cleanup();
    process.exit(130);
  });
}
const overall = setTimeout(() => {
  console.log(`FAIL overall timeout of ${TIMEOUT_MS} ms`);
  cleanup();
  process.exit(1);
}, TIMEOUT_MS);
overall.unref();

async function withTimeout(promise, ms, what) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(`timed out after ${ms} ms waiting for ${what}`)), ms);
  });
  try {
    return await Promise.race([promise, timeout]);
  } finally {
    clearTimeout(timer);
  }
}

// A routable address of this host, so ICE has a real candidate pair to check (a browser never
// gathers loopback). Falls back to loopback.
function hostAddress() {
  for (const addresses of Object.values(os.networkInterfaces())) {
    for (const address of addresses ?? []) {
      if (address.family === "IPv4" && !address.internal) return address.address;
    }
  }
  return "127.0.0.1";
}

async function freePort() {
  return await new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });
}

// ---------------------------------------------------------------- engine control

class Control {
  constructor(socket) {
    this.socket = socket;
    this.buffer = Buffer.alloc(0);
    this.nextId = 1;
    this.pending = new Map();
    this.events = [];
    this.waiters = [];
    socket.on("data", (chunk) => {
      this.buffer = Buffer.concat([this.buffer, chunk]);
      while (this.buffer.length >= 4) {
        const length = this.buffer.readUInt32BE(0);
        if (this.buffer.length < 4 + length) break;
        const frame = JSON.parse(this.buffer.subarray(4, 4 + length).toString("utf8"));
        this.buffer = this.buffer.subarray(4 + length);
        this.dispatch(frame);
      }
    });
  }

  dispatch(frame) {
    if (frame.id !== undefined && this.pending.has(frame.id)) {
      this.pending.get(frame.id)(frame);
      this.pending.delete(frame.id);
      return;
    }
    if (frame.event) {
      this.events.push(frame);
      this.waiters = this.waiters.filter((waiter) => !waiter());
    }
  }

  async call(command) {
    const id = this.nextId++;
    const body = Buffer.from(JSON.stringify({ id, ...command }));
    const header = Buffer.alloc(4);
    header.writeUInt32BE(body.length);
    const reply = new Promise((resolve) => this.pending.set(id, resolve));
    this.socket.write(Buffer.concat([header, body]));
    return await withTimeout(reply, 15000, `reply to ${command.command}`);
  }

  async nextEvent(match, ms, what) {
    const find = () => this.events.findIndex(match);
    return await withTimeout(
      new Promise((resolve) => {
        const check = () => {
          const index = find();
          if (index < 0) return false;
          resolve(this.events.splice(index, 1)[0]);
          return true;
        };
        if (!check()) this.waiters.push(check);
      }),
      ms,
      what,
    );
  }
}

async function startEngine(address) {
  const controlPort = await freePort();
  const engine = spawn(
    process.env.ENGINE_BIN,
    ["--control", `127.0.0.1:${controlPort}`, "--relay-bind-ip", address],
    { stdio: ["ignore", "inherit", "inherit"], env: { ...process.env, RUST_LOG: process.env.RUST_LOG ?? "info" } },
  );
  cleanups.push(() => engine.kill("SIGKILL"));
  engine.once("exit", (code, signal) => {
    if (!cleaned) {
      console.log(`FAIL engine exited early (code ${code}, signal ${signal})`);
      cleanup();
      process.exit(1);
    }
  });
  for (let attempt = 0; attempt < 100; attempt += 1) {
    try {
      const socket = await new Promise((resolve, reject) => {
        const connection = net.connect(controlPort, "127.0.0.1", () => resolve(connection));
        connection.once("error", reject);
      });
      cleanups.push(() => socket.destroy());
      return new Control(socket);
    } catch {
      await sleep(100);
    }
  }
  throw new Error("engine control port never opened");
}

// ---------------------------------------------------------------- Chrome DevTools

async function startChrome() {
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), "floor-chrome-"));
  const chrome = spawn(
    process.env.CHROME_BIN,
    [
      "--headless=new",
      "--remote-debugging-port=0",
      `--user-data-dir=${profile}`,
      "--no-first-run",
      "--no-default-browser-check",
      "--no-sandbox",
      "--disable-gpu",
      "--disable-dev-shm-usage",
      "--autoplay-policy=no-user-gesture-required",
      "about:blank",
    ],
    { stdio: ["ignore", "ignore", "ignore"] },
  );
  cleanups.push(() => {
    chrome.kill("SIGKILL");
    fs.rmSync(profile, { recursive: true, force: true });
  });
  const portFile = path.join(profile, "DevToolsActivePort");
  let port;
  for (let attempt = 0; attempt < 200 && !port; attempt += 1) {
    if (fs.existsSync(portFile)) {
      port = Number(fs.readFileSync(portFile, "utf8").split("\n")[0]);
    } else {
      await sleep(100);
    }
  }
  if (!port) throw new Error("Chrome never wrote DevToolsActivePort");
  const target = await (await fetch(`http://127.0.0.1:${port}/json/new?about:blank`, { method: "PUT" })).json();
  const socket = new WebSocket(target.webSocketDebuggerUrl);
  await new Promise((resolve, reject) => {
    socket.onopen = resolve;
    socket.onerror = () => reject(new Error("DevTools websocket failed"));
  });
  let nextId = 1;
  const pending = new Map();
  socket.onmessage = (message) => {
    const frame = JSON.parse(message.data);
    if (frame.id !== undefined && pending.has(frame.id)) {
      pending.get(frame.id)(frame);
      pending.delete(frame.id);
    }
  };
  const send = (method, params = {}) => {
    const id = nextId++;
    const reply = new Promise((resolve) => pending.set(id, resolve));
    socket.send(JSON.stringify({ id, method, params }));
    return reply;
  };
  const version = await (await fetch(`http://127.0.0.1:${port}/json/version`)).json();
  console.log(`chrome: ${version.Browser}`);
  return {
    async evaluate(expression, ms = 30000) {
      const reply = await withTimeout(
        send("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true }),
        ms,
        "page evaluation",
      );
      if (reply.error) throw new Error(JSON.stringify(reply.error));
      if (reply.result.exceptionDetails) {
        throw new Error(reply.result.exceptionDetails.exception?.description ?? reply.result.exceptionDetails.text);
      }
      return reply.result.result.value;
    },
  };
}

// ---------------------------------------------------------------- the scenario

// The page's audio source and the floor channel plumbing both directions share.
const PAGE_PRELUDE = `
  const context = new AudioContext();
  const oscillator = context.createOscillator();
  oscillator.type = "sawtooth";
  oscillator.frequency.value = 440;
  const destination = context.createMediaStreamDestination();
  oscillator.connect(destination);
  oscillator.start();
  await context.resume();
  const pc = new RTCPeerConnection({});
  window.pc = pc;
  window.messages = [];
  window.channelState = "connecting";
  const track = destination.stream.getAudioTracks()[0];
  const attachFloor = () => {
    const floor = pc.createDataChannel("mcptt-floor");
    floor.binaryType = "arraybuffer";
    floor.onopen = () => { window.channelState = "open"; };
    floor.onclose = () => { window.channelState = "closed"; };
    floor.onmessage = (event) => {
      window.messages.push({ binary: event.data instanceof ArrayBuffer, bytes: Array.from(new Uint8Array(event.data)) });
    };
    window.floor = floor;
  };
  const gathered = new Promise((resolve) => {
    pc.onicegatheringstatechange = () => { if (pc.iceGatheringState === "complete") resolve(); };
    setTimeout(resolve, 5000);
  });
`;

// forward_join: the browser offers.
const PAGE_OFFER = `(async () => {
  ${PAGE_PRELUDE}
  pc.addTrack(track, destination.stream);
  attachFloor();
  await pc.setLocalDescription(await pc.createOffer());
  await gathered;
  return pc.localDescription.sdp;
})()`;

// forward_offer: the browser answers. It sets the engine's offer, then opens the floor channel on the
// section the offer carries (createDataChannel after setRemoteDescription reuses the offered
// m=application) and sends audio on the offered audio section.
const pageAnswer = (offer) => `(async () => {
  ${PAGE_PRELUDE}
  await pc.setRemoteDescription({ type: "offer", sdp: ${JSON.stringify(offer)} });
  const audio = pc.getTransceivers().find((transceiver) => transceiver.receiver.track.kind === "audio");
  audio.direction = "sendrecv";
  await audio.sender.replaceTrack(track);
  attachFloor();
  await pc.setLocalDescription(await pc.createAnswer());
  await gathered;
  return pc.localDescription.sdp;
})()`;

async function main() {
  if (!process.env.ENGINE_BIN || !process.env.CHROME_BIN) {
    throw new Error("ENGINE_BIN and CHROME_BIN are required");
  }
  const address = hostAddress();
  console.log(`engine media address: ${address}`);
  const control = await startEngine(address);
  const chrome = await startChrome();

  const node = await control.call({ command: "node_info" });
  const features = JSON.stringify(node.node?.features ?? node.features ?? []);
  for (const feature of ["webrtc_floor_channel", "forward_offer_webrtc"]) {
    if (!features.includes(feature)) {
      throw new Error(`engine lacks ${feature}: ${JSON.stringify(node).slice(0, 300)}`);
    }
  }

  // Each direction runs in a room of its own, on the same engine and browser.
  for (const direction of ["join", "offer"]) {
    console.log(`--- ${direction === "join" ? "the browser calls the room (forward_join)" : "the room calls the browser (forward_offer)"}`);
    await scenario(direction, control, chrome);
  }
}

// The floor parameters that mark a room as carrying floor control (3GPP TS 24.380 section 14).
const FLOOR_FMTP = "mc_queueing;mc_priority=5;mc_granted";

async function scenario(direction, control, chrome) {
  const ROOM = `${ROOM_PREFIX}-${direction}`;
  const label = (name) => `${direction}: ${name}`;
  let answer;
  if (direction === "join") {
    const offer = await chrome.evaluate(PAGE_OFFER);
    const mdns = (offer.match(/a=candidate:.* [0-9a-f-]+\.local /g) ?? []).length;
    console.log(`browser offer: ${offer.split("\r\n").length} lines, ${mdns} mDNS candidate(s)`);
    if (mdns === 0) console.log("note: this Chrome offered no mDNS host candidate");

    const joined = await control.call({
      command: "forward_join",
      conference_id: ROOM,
      from_tag: BROWSER_TAG,
      sdp: offer,
      profile: {},
    });
    if (joined.result !== "ok" || !joined.sdp) {
      throw new Error(`forward_join for the browser failed: ${JSON.stringify(joined)}`);
    }
    answer = joined.sdp;
  } else {
    const offered = await control.call({
      command: "forward_offer",
      conference_id: ROOM,
      from_tag: BROWSER_TAG,
      profile: { transport_protocol: "UDP/TLS/RTP/SAVPF", floor_fmtp: FLOOR_FMTP },
    });
    if (offered.result !== "ok" || !offered.sdp) {
      throw new Error(`forward_offer for the browser failed: ${JSON.stringify(offered)}`);
    }
    const engineOffer = offered.sdp;
    for (const required of ["UDP/TLS/RTP/SAVPF", "a=ice-lite", "a=setup:actpass", "webrtc-datachannel"]) {
      if (!engineOffer.includes(required)) throw new Error(`the engine's offer lacks ${required}:\n${engineOffer}`);
    }
    const browserAnswer = await chrome.evaluate(pageAnswer(engineOffer));
    const accepted = (browserAnswer.match(/^m=application [1-9]/gm) ?? []).length;
    console.log(`browser answer: ${browserAnswer.split("\r\n").length} lines, data channel section ${accepted ? "kept" : "DECLINED"}`);
    const seated = await control.call({
      command: "forward_answer",
      conference_id: ROOM,
      from_tag: BROWSER_TAG,
      sdp: browserAnswer,
    });
    if (seated.result !== "ok") {
      throw new Error(`forward_answer for the browser failed: ${JSON.stringify(seated)}\n${browserAnswer}`);
    }
    answer = engineOffer;
  }

  // A plain RTP listener seat in the room's codec (Opus, fixed by the first seat), so the browser's
  // audio can be seen to arrive at the far end of the engine.
  const listener = dgram.createSocket("udp4");
  await new Promise((resolve) => listener.bind(0, "127.0.0.1", resolve));
  cleanups.push(() => listener.close());
  const received = { packets: 0, payloadTypes: new Set() };
  listener.on("message", (packet) => {
    if (packet.length >= 12 && packet[0] >> 6 === 2) {
      received.packets += 1;
      received.payloadTypes.add(packet[1] & 0x7f);
    }
  });
  const listenerPort = listener.address().port;
  const listenerOffer = [
    "v=0",
    "o=- 1 1 IN IP4 127.0.0.1",
    "s=-",
    "t=0 0",
    `m=audio ${listenerPort} RTP/AVP 111`,
    "c=IN IP4 127.0.0.1",
    "a=rtpmap:111 opus/48000/2",
    "a=fmtp:111 minptime=10;useinbandfec=1",
    "a=sendrecv",
    "",
  ].join("\r\n");
  const listenerJoin = await control.call({
    command: "forward_join",
    conference_id: ROOM,
    from_tag: LISTENER_TAG,
    sdp: listenerOffer,
    profile: {},
  });
  if (listenerJoin.result !== "ok") {
    throw new Error(`forward_join for the listener failed: ${JSON.stringify(listenerJoin)}`);
  }
  const source = await control.call({ command: "forward_set_source", conference_id: ROOM, from_tag: BROWSER_TAG });
  if (source.result !== "ok") throw new Error(`forward_set_source failed: ${JSON.stringify(source)}`);

  if (direction === "join") {
    await chrome.evaluate(
      `window.pc.setRemoteDescription({ type: "answer", sdp: ${JSON.stringify(answer)} }).then(() => "ok")`,
    );
  }

  // 1. the data channel opens (ICE, DTLS, SCTP and DCEP all completed with the browser).
  try {
    await withTimeout(
      (async () => {
        while ((await chrome.evaluate("window.channelState")) !== "open") await sleep(200);
      })(),
      30000,
      "the data channel to open",
    );
    pass(label("data channel reaches open"));
  } catch (error) {
    fail(label("data channel reaches open"), error.message);
    console.log(`browser connection state: ${await chrome.evaluate("window.pc.connectionState + ' ice=' + window.pc.iceConnectionState")}`);
    console.log(`engine answer:\n${answer}`);
    return;
  }

  // 2. Floor Request from the page arrives as an rtcp_app event.
  await chrome.evaluate(`window.floor.send(new Uint8Array(${JSON.stringify(FLOOR_REQUEST)})); "sent"`);
  try {
    const event = await control.nextEvent((frame) => frame.event === "rtcp_app", 10000, "the rtcp_app event");
    const payload = Array.from(Buffer.from(event.payload, "base64"));
    const expected = {
      conference_id: ROOM,
      from_tag: BROWSER_TAG,
      stream: "floor",
      ssrc: 0x11223344,
      name: "MCPT",
      subtype: 0,
    };
    const wrong = Object.entries(expected).filter(([key, value]) => event[key] !== value);
    if (wrong.length === 0 && hex(payload) === hex(FLOOR_REQUEST.slice(12))) {
      pass(label("floor request reaches the controller as rtcp_app"), `subtype 0, name MCPT, payload ${hex(payload)}`);
    } else {
      fail(label("floor request reaches the controller as rtcp_app"), JSON.stringify(event));
    }
  } catch (error) {
    fail(label("floor request reaches the controller as rtcp_app"), error.message);
  }

  // 3. the controller's Floor Granted arrives in the page byte for byte.
  const sent = await control.call({
    command: "send_rtcp_app",
    conference_id: ROOM,
    from_tag: BROWSER_TAG,
    stream: "floor",
    ssrc: GRANT_SSRC,
    name: "MCPT",
    subtype: GRANT_SUBTYPE,
    payload: Buffer.from(FLOOR_GRANTED_PAYLOAD).toString("base64"),
  });
  if (sent.result !== "ok") {
    fail(label("floor granted arrives in the page byte-identical"), `send_rtcp_app: ${JSON.stringify(sent)}`);
  } else {
    try {
      const messages = await withTimeout(
        (async () => {
          for (;;) {
            const seen = await chrome.evaluate("window.messages");
            if (seen.length > 0) return seen;
            await sleep(100);
          }
        })(),
        10000,
        "the floor message in the page",
      );
      const [message] = messages;
      if (messages.length === 1 && message.binary && hex(message.bytes) === hex(FLOOR_GRANTED)) {
        pass(label("floor granted arrives in the page byte-identical"), hex(message.bytes));
      } else {
        fail(label("floor granted arrives in the page byte-identical"), `got ${JSON.stringify(messages)}, want ${hex(FLOOR_GRANTED)}`);
      }
    } catch (error) {
      fail(label("floor granted arrives in the page byte-identical"), error.message);
    }
  }

  // 4. the browser's audio RTP reaches the engine and is forwarded to the listener seat.
  try {
    await withTimeout(
      (async () => {
        while (received.packets < 20) await sleep(100);
      })(),
      15000,
      "audio at the listener seat",
    );
    pass(label("browser audio RTP reaches the engine"), `${received.packets} packets forwarded, payload type(s) ${[...received.payloadTypes].join(",")}`);
  } catch (error) {
    fail(label("browser audio RTP reaches the engine"), `${error.message}; ${received.packets} packets`);
  }
}

try {
  await main();
} catch (error) {
  fail("scenario", error.stack ?? String(error));
}
cleanup();
console.log(failures === 0 ? "ALL PASS" : `${failures} FAILED`);
process.exit(failures === 0 ? 0 : 1);
