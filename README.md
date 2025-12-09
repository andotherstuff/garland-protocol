# Garland Protocol

Durable, private, personal storage built on Nostr and Blossom infrastructure.

## Goal

Garland is a distributed storage system that lets you back up personal data across multiple independent servers while maintaining complete privacy. Your data survives server failures, and the entire dataset is recoverable from a single cryptographic key.

**Core properties:**

- **Durable** — Erasure coding or simple replication across n servers; survives arbitrary server failures
- **Private** — Servers see only fixed-size encrypted blobs; they learn nothing about content, filenames, or structure
- **Recoverable** — Everything reconstructable from your Nostr key (nsec)
- **Simple** — Storage servers stay "dumb"—just PUT and GET opaque blobs

## How It Works

Files are chunked into fixed-size blocks, encrypted, erasure-coded into shares, and distributed across Blossom servers. A hierarchical namespace (like a filesystem) is maintained via content-addressed manifests stored the same way. The root pointer lives on Nostr relays as a signed event.

See [garland-v0.md](garland-v0.md) and [garland-v0.1.md](garland-v0.1.md) for the design documents.

## Changelog: v0 → v0.1

**State Management**
- *v0:* Single replaceable Nostr event (kind 30097) storing current root hash
- *v0.1:* Hash chain of commit events with `prev` tag linking to predecessor, enabling full history traversal, conflict detection, and auditability

**Conflict Handling**
- *v0:* Undefined — last-write-wins with silent data loss
- *v0.1:* Commits reference parent via `prev` tag; clients detect divergence before committing and must reconcile

**Garbage Collection**
- *v0:* "Orphaned shares eventually garbage-collected by servers" (undefined mechanism)
- *v0.1:* Explicit client responsibility with reference tracking, deletion strategies, and `garbage` field in commits announcing deleted blobs

**Verification and Repair**
- *v0:* Dedicated steward service running independently with owner's nsec; verifies via range requests
- *v0.1:* Multiple verification approaches (HEAD requests, byte range verification, fuse filters) with tradeoff analysis; steward service model; explicit repair flow

**Update Model**
- *v0:* Implicit copy-on-write with unspecified commit timing
- *v0.1:* Explicit snapshot-based workflow — changes accumulate locally, committed via deliberate save action

**Metadata Events**
- *v0:* No guidance on pruning old events
- *v0.1:* Explicit strategy for garbage collecting old commit events from relays while preserving designated snapshots

**Passphrase-Protected Storage Identities**
- *v0:* Not supported — nsec alone controls all data
- *v0.1:* Optional passphrase derives a separate storage identity (Section 6.4); enables defense in depth and plausible deniability with independent, unlinkable storage buckets

**Large File Handling**
- *v0:* Inode size unbounded — large files could exceed block limits
- *v0.1:* Indirect block structure for files exceeding ~500 blocks; bounds inode size regardless of file size

**Commit Ordering**
- *v0:* Replaceable event with implicit ordering
- *v0.1:* No sequence counter; head discovery via `limit=1` relay query (reverse chronological); chain traversal via `prev` tags for full history

**Encryption**
- *v0:* ChaCha20-Poly1305 or AES-GCM (underspecified)
- *v0.1:* ChaCha20 with 12-byte nonce; integrity via content addressing (SHA-256 share IDs + plaintext block hashes in inodes)

**Erasure Coding**
- *v0:* Required; parameters unspecified
- *v0.1:* Optional; k=1 enables simple replication (n identical copies, no encoding), k>1 enables erasure coding; parameter table with overhead/tolerance tradeoffs

**Blossom Authentication**
- *v0:* Single pubkey for all uploads (allows server correlation)
- *v0.1:* Per-blob derived authentication keys by default; each blob appears to come from a different user; optional identity key mode for billing

**Privacy Analysis**
- *v0:* Section on "What Servers Observe"
- *v0.1:* Expanded to dedicated section covering Blossom servers, Nostr relays, cross-server correlation, and information leak summary with mitigations

## Status

This is early architecture research. The design documents are ready for feedback—no implementation exists yet.

If you have thoughts, questions, or concerns about the approach, please open an issue.

## License

MIT
