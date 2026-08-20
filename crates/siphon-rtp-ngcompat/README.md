# siphon-rtp-ngcompat

The rtpengine NG / bencode-over-UDP control front-end for
[siphon-rtp](https://github.com/siphon-project/siphon-rtp).

Lets existing Kamailio / OpenSIPS / FreeSWITCH deployments (and SIPhon's bencode rtpengine client)
drive siphon-rtp unchanged: it parses the NG bencode protocol into the internal command set and
serializes the results back. Control-protocol parity only — the in-kernel path is XDP, not the
rtpengine kernel module.

```toml
[dependencies]
siphon-rtp-ngcompat = "0.2"
```

## License

MIT
