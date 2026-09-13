# Canvas Messenger — Relay Server

The REST API + message relay backend for [Canvas Messenger](https://github.com/Hackatoan/canvas-messenger), a Discord-style messaging layer for Canvas LMS.

☕ **Support:** [Buy Me a Coffee](https://buymeacoffee.com/hackatoa)

## Overview

`cm-relay` handles account registration, auth tokens, invite links, and relaying messages between Canvas Messenger clients. It pairs with [`cm-signaling`](https://github.com/Hackatoan/cm-signaling) (WebRTC signaling) and the [`canvas-messenger`](https://github.com/Hackatoan/canvas-messenger) browser extension.

## Features

- User registration + bearer-token auth (tokens generated server-side)
- Invite-link creation and lookup
- Message relay between peers
- Stateless, container-friendly

## Tech Stack

Node.js · Express · Docker

## Development

```bash
npm install
PORT=3000 npm start   # defaults to :3000
```

## Deployment

Docker image `ghcr.io/hackatoan/cm-relay:latest` built by GitHub Actions; runs on the homelab behind NPMplus at `relay.hackatoa.com`.

## Support

If this project is useful to you, consider supporting development:

☕ **[Buy Me a Coffee](https://buymeacoffee.com/hackatoa)**

---

Part of the **[Hackatoa](https://hackatoa.com)** ecosystem — self-hosted apps, browser games, and bots. · [All repositories »](https://github.com/Hackatoan)

