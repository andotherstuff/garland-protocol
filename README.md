# Garland Protocol

Durable, private, personal storage built on Nostr and Blossom infrastructure.

## Goal

Garland is a distributed storage system that lets you back up personal data across multiple independent servers while maintaining complete privacy. Your data survives server failures, and the entire dataset is recoverable from a single cryptographic key.

**Core properties:**

- **Durable** — Erasure coding (n, k) means data survives arbitrary server failures
- **Private** — Servers see only fixed-size encrypted blobs; they learn nothing about content, filenames, or structure
- **Recoverable** — Everything reconstructable from your Nostr key (nsec)
- **Simple** — Storage servers stay "dumb"—just PUT and GET opaque blobs

## How It Works

Files are chunked into fixed-size blocks, encrypted, erasure-coded into shares, and distributed across Blossom servers. A hierarchical namespace (like a filesystem) is maintained via content-addressed manifests stored the same way. The root pointer lives on Nostr relays as a signed event.

See [v0](v0/) and [v0.1](v0.1/) for the design documents.

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
- *v0.1:* Client verifies via HEAD requests, range requests, or potential future filters; steward deferred to future work

**Update Model**
- *v0:* Implicit copy-on-write with unspecified commit timing
- *v0.1:* Explicit snapshot-based workflow — changes accumulate locally, committed via deliberate save action

**Metadata Events**
- *v0:* No guidance on pruning old events
- *v0.1:* Explicit strategy for garbage collecting old commit events from relays while preserving designated snapshots

**Passphrase-Protected Storage Identities** *(new in v0.1)*
- Optional passphrase derives a separate storage identity (nsec + passphrase → derived nsec)
- Defense in depth: nsec compromise alone reveals nothing
- Plausible deniability: multiple passphrases create independent, unlinkable storage buckets
- Uses only existing Nostr primitives (PBKDF2-HMAC-SHA256, no new dependencies)
- Zero protocol changes: derived nsec used transparently throughout

## Status

This is early architecture research. The design documents are ready for feedback—no implementation exists yet.

If you have thoughts, questions, or concerns about the approach, please open an issue.

## License

MIT
