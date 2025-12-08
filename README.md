# Garland Protocol

Durable, private, personal storage built on Nostr and Blossom infrastructure.

## Goal

Garland is a distributed storage system that lets you back up personal data across multiple independent servers while maintaining complete privacy. Your data survives server failures, and the entire dataset is recoverable from a single cryptographic key.

**Core properties:**

- **Durable** — Erasure coding (k-of-n) means data survives arbitrary server failures
- **Private** — Servers see only fixed-size encrypted blobs; they learn nothing about content, filenames, or structure
- **Recoverable** — Everything reconstructable from your Nostr key (nsec)
- **Simple** — Storage servers stay "dumb"—just PUT and GET opaque blobs

## How It Works

Files are chunked into fixed-size blocks, encrypted, erasure-coded into shares, and distributed across Blossom servers. A hierarchical namespace (like a filesystem) is maintained via content-addressed manifests stored the same way. The root pointer lives on Nostr relays as a signed event.

See [v0](v0/) for the full design document.

## Status

This is early architecture research. The design documents are ready for feedback—no implementation exists yet.

If you have thoughts, questions, or concerns about the approach, please open an issue.

## License

MIT
