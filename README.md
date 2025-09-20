# WebRTC-SIP Bridge

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

A WebRTC to SIP gateway that bridges browser-based VoIP clients with traditional SIP infrastructure. Enables click-to-call from web browsers to enterprise PBX systems, SIP trunks, and PSTN via SIP.

## Architecture

```
  Signaling Path:
  ┌──────────┐  WebSocket   ┌──────────────┐   SIP/UDP    ┌──────────┐
  │  Browser │◄────────────►│   Gateway    │◄────────────►│  SIP     │
  │  (WebRTC)│  JSON msgs   │   Server     │  RFC 3261    │  PBX/SBC │
  └──────────┘              └──────────────┘              └──────────┘

  Media Path:
  ┌──────────┐  SRTP/DTLS   ┌──────────────┐   RTP        ┌──────────┐
  │  Browser │◄────────────►│  Media Relay │◄────────────►│  SIP     │
  │          │  ICE/STUN    │              │              │  Endpoint│
  └──────────┘              └──────────────┘              └──────────┘
```

## Key Features

- **SDP Translation** — WebRTC SDP ↔ SIP SDP with ICE, DTLS-SRTP, BUNDLE, rtcp-mux handling
- **SIP Stack** — Full RFC 3261 transaction layer (INVITE/non-INVITE state machines)
- **Dialog Management** — SIP dialog lifecycle (Early → Confirmed → Terminated)
- **WebSocket Signaling** — JSON-based signaling protocol for browser clients
- **Call Routing** — E.164 dial plan with pattern matching and trunk selection
- **DTMF Support** — RFC 2833 ↔ SIP INFO interworking
- **Media Relay** — RTP forwarding with SRTP ↔ RTP translation
- **Authentication** — SIP digest auth and WebRTC token-based auth
- **Web Softphone** — Built-in browser softphone with dialpad UI

## SDP Translation (WebRTC ↔ SIP)

The gateway handles the critical differences between WebRTC and SIP SDP:

| WebRTC SDP | SIP SDP | Gateway Action |
|------------|---------|----------------|
| a=fingerprint (DTLS) | Not present | Strip for SIP, add for WebRTC |
| a=ice-ufrag/pwd | Not present | Strip for SIP, generate for WebRTC |
| a=group:BUNDLE | Not present | Remove bundling for SIP |
| a=rtcp-mux | Optional | Negotiate separately |
| a=setup:actpass | Not present | Handle DTLS role |
| SRTP (encrypted) | RTP (plain) | Media relay translates |

## Quick Start

```bash
# Docker
docker-compose -f docker/docker-compose.yml up -d

# From source
pip install -e .
python -m gateway.server --config config/gateway.yaml
```

Then open `http://localhost:8080` for the web softphone.

## Technology Stack

- **Python 3.10+** with asyncio
- **WebSocket** signaling (websockets library)
- **JavaScript** WebRTC client
- **SIP** RFC 3261 implementation
- **Docker** deployment

## License

MIT License — see [LICENSE](LICENSE) for details.
