# Nostr-Native Distributed Storage System

**A Design for Erasure-Coded, Privacy-Preserving Blob Storage**

Design Document
December 4, 2025

---

## Abstract

This document describes a distributed storage system built on Nostr and Blossom infrastructure. The system provides durable, privacy-preserving storage for immutable blobs using erasure coding across independent servers. A hierarchical namespace (analogous to a filesystem) is maintained through content-addressed manifests, with the entire structure recoverable from a single cryptographic key. A separate steward service handles ongoing verification and repair without requiring the client to remain online.

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Design Goals](#2-design-goals)
3. [Architecture Overview](#3-architecture-overview)
4. [Block Layer](#4-block-layer)
5. [Erasure Coding Layer](#5-erasure-coding-layer)
6. [Inode Structure](#6-inode-structure)
7. [Directory Hierarchy](#7-directory-hierarchy)
8. [Root Event (The Superblock)](#8-root-event-the-superblock)
9. [Single-Key Discovery](#9-single-key-discovery)
10. [Transport Layer](#10-transport-layer)
11. [Verification and Repair](#11-verification-and-repair)
12. [What Servers Observe](#12-what-servers-observe)
13. [Lifecycle Summary](#13-lifecycle-summary)
14. [Future Considerations](#14-future-considerations)
15. [Conclusion](#15-conclusion)

---

## 1. Introduction

The system addresses a common need: reliable long-term storage of personal data across unreliable infrastructure. Individual storage providers (relays, blossom servers) may disappear without warning, yet data should survive as long as a sufficient subset of providers remains operational.

Key requirements:

- **Durability**: Tolerate arbitrary server failures up to a configurable threshold
- **Privacy**: Servers learn nothing about stored content, file sizes, or structure
- **Simplicity**: Storage servers remain "dumb"—they store and retrieve opaque blobs
- **Recovery**: The entire dataset is recoverable from a single secret key
- **Autonomy**: Verification and repair can run independently of the client

---

## 2. Design Goals

### 2.1 Threat Model

Servers are assumed to be honest-but-curious and unreliable:

- They will store data if paid or incentivized
- They may inspect stored data
- They may disappear without notice
- They will not actively corrupt data (detectable via content addressing)

The system does not protect against a coordinated attack where > n − k servers collude to destroy data simultaneously.

### 2.2 Non-Goals

- **Mutability**: Blobs are immutable and content-addressed. Updates create new blobs.
- **Sharing**: This design focuses on single-owner storage. Multi-user access control is out of scope.
- **Real-time access**: The system is optimized for backup/archival, not low-latency random access.

---

## 3. Architecture Overview

The system is organized into layers, each with a single responsibility:

```
┌─────────────────────────────────────────────────────────┐
│           Namespace Layer (paths → inodes)              │
├─────────────────────────────────────────────────────────┤
│         Inode Layer (file metadata, block lists)        │
├─────────────────────────────────────────────────────────┤
│        Block Layer (fixed-size, encrypted chunks)       │
├─────────────────────────────────────────────────────────┤
│          Erasure Coding Layer (k-of-n shares)           │
├─────────────────────────────────────────────────────────┤
│     Transport Layer (Blossom PUT/GET, Nostr events)     │
└─────────────────────────────────────────────────────────┘
```

Data flows downward on write (files are chunked, encrypted, erasure-coded, and distributed) and upward on read (shares are fetched, decoded, decrypted, and reassembled).

---

## 4. Block Layer

### 4.1 Fixed-Size Blocks

All data is divided into fixed-size blocks before storage. A typical block size is 256 KB, though this is configurable.

For a file of size S bytes:

```
N_blocks = ⌈S / B⌉
```

where B is the block size. The final block is padded to exactly B bytes.

### 4.2 Privacy Through Uniformity

Fixed-size blocks are essential for privacy. If all stored blobs are exactly the same size, observers cannot:

- Distinguish small files from chunks of large files
- Infer file types from size patterns
- Correlate related blobs by size similarity
- Determine whether a blob is data or metadata

### 4.3 Encryption

Each block is encrypted before leaving the client. For a file with encryption key K_f, block i is encrypted with a derived key:

```
K_i = KDF(K_f ∥ i)
```

The encryption scheme should be an authenticated encryption mode (e.g., ChaCha20-Poly1305 or AES-GCM). The file key K_f is randomly generated per file and stored in the file's inode, encrypted to the owner's public key.

After encryption, each block is indistinguishable from random data.

---

## 5. Erasure Coding Layer

### 5.1 Reed-Solomon Coding

Each encrypted block is erasure-coded into n shares using a k-of-n scheme. Any k shares suffice to reconstruct the original block.

The encoding treats the block as coefficients of a polynomial over GF(2⁸):

```
P(x) = b₀ + b₁x + b₂x² + ⋯ + b_{k-1}x^{k-1}
```

where b_i are bytes of the (padded) block. Shares are evaluations of P(x) at n distinct points.

### 5.2 Parameters

Typical configurations:

| k | n | Overhead | Tolerance |
|---|---|----------|-----------|
| 2 | 3 | 1.5×     | 1 server failure |
| 3 | 5 | 1.67×    | 2 server failures |
| 4 | 7 | 1.75×    | 3 server failures |

Higher n − k increases durability but also increases storage cost and the number of servers required.

### 5.3 Share Addressing

Each share is content-addressed by the hash of its ciphertext:

```
share_id = H(share_bytes)
```

Servers store and retrieve shares solely by this identifier. They have no knowledge of which file or block a share belongs to.

---

## 6. Inode Structure

An inode contains all information needed to reconstruct a file:

```json
{
  "type": "file",
  "size": 10485760,
  "key": "<file encryption key, encrypted to owner>",
  "blocks": [
    {
      "hash": "<hash of plaintext block for integrity>",
      "shares": [
        {"id": "<share0_hash>", "url": "<blossom_url>"},
        {"id": "<share1_hash>", "url": "<blossom_url>"},
        {"id": "<share2_hash>", "url": "<blossom_url>"}
      ]
    },
    ...
  ],
  "erasure": {"k": 2, "n": 3, "field": "gf256"}
}
```

The inode itself is stored as a blob: encrypted, chunked, erasure-coded, and distributed exactly like file data. This recursive structure means servers cannot distinguish file content from metadata.

---

## 7. Directory Hierarchy

### 7.1 Directories as Files

A directory is simply a file whose decrypted contents map names to inode blob identifiers:

```json
{
  "type": "directory",
  "entries": {
    "photos/": "<inode_blob_hash>",
    "documents/": "<inode_blob_hash>",
    "notes.txt": "<inode_blob_hash>"
  }
}
```

This is encrypted and stored identically to file inodes. From a server's perspective, all blobs are indistinguishable.

### 7.2 Single Root

The entire hierarchy is anchored by a single root directory. The root's inode hash is the only piece of information needed (beyond the decryption key) to traverse the full tree.

```
                    ┌────────────────┐
                    │ Root Directory │
                    └───────┬────────┘
                            │
           ┌────────────────┼────────────────┐
           │                │                │
           ▼                ▼                ▼
    ┌──────────┐     ┌────────────┐    ┌───────────┐
    │ photos/  │     │ documents/ │    │ notes.txt │
    └────┬─────┘     └─────┬──────┘    └───────────┘
         │                 │
         ▼                 ▼
   ┌───────────┐    ┌────────────┐
   │ image1.jpg│    │ report.pdf │
   └───────────┘    └────────────┘
```

Each arrow represents a content-addressed reference (hash). The structure is a Merkle DAG.

### 7.3 Updates

Adding or modifying a file requires:

1. Create and upload the new file's blocks and inode
2. Reconstruct the parent directory, add/update the entry, re-upload
3. Recursively update ancestors up to the root
4. Publish the new root hash

This is copy-on-write semantics. Old versions remain intact until garbage collected.

---

## 8. Root Event (The Superblock)

The root hash is published as a Nostr replaceable event, signed by the owner's key:

```json
{
  "kind": 30097,
  "d": "storage-root",
  "content": "<encrypted>",
  "tags": [...]
}
```

The encrypted content contains:

```json
{
  "root_blob": "<content hash of root directory inode>",
  "k": 2,
  "n": 3,
  "shares": [
    {"id": "...", "url": "..."},
    ...
  ]
}
```

This event is small (a few kilobytes) and stored on regular Nostr relays with high replication. It is the only mutable pointer in the system.

---

## 9. Single-Key Discovery

Disaster recovery requires only the owner's secret key (nsec):

1. Derive public key: nsec → npub
2. Query Nostr relays for kind:30097 events by author npub
3. Decrypt the root event content using nsec
4. Fetch k shares of the root directory inode from listed URLs
5. Reconstruct and decrypt the root directory
6. Recursively traverse to recover any file

No external database, no secondary credentials, no trusted third party. The Nostr relay network serves as the discovery layer.

---

## 10. Transport Layer

### 10.1 Blossom Servers

Blossom servers provide content-addressed blob storage over HTTP:

- `PUT /upload` — store a blob, returns its hash
- `GET /<hash>` — retrieve a blob by hash
- `HEAD /<hash>` — check existence

Servers are interchangeable. A share can be uploaded to any server; only its URL needs recording.

### 10.2 Small Blob Optimization

For blobs smaller than a threshold (e.g., 4 KB), storage as Nostr events may be more practical:

- Higher replication (events propagate across many relays)
- No separate blossom server dependency
- Slight privacy leak (observers know something is "small")

For a personal backup system, padding small files to the standard block size is simpler and preserves uniformity.

---

## 11. Verification and Repair

### 11.1 The Steward Service

A steward is a process (potentially running on a separate machine) that:

1. Periodically reads the owner's manifests
2. Challenges each share location to verify data availability
3. Detects failures and initiates repair
4. Updates manifests with new share locations after repair

The steward requires read access to manifests and credentials to upload replacement shares. In the simplest model, it holds the owner's nsec or a delegated key.

### 11.2 Challenge Protocol

For "dumb" servers, challenges are simple:

1. Request a byte range [offset, offset + len) from the share
2. Hash the response
3. Verify against the expected hash (derived from the share's content hash)

This samples the share without downloading it entirely. The server performs only a seek and read.

Alternatively, request the full share hash:

```
H(share_bytes) = share_id
```

If the server cannot produce a matching hash, the share is considered lost.

### 11.3 Repair Flow

When share i of block b is lost:

1. Fetch any k surviving shares of block b
2. Reconstruct the original block using erasure decoding
3. Re-encode to produce the missing share i
4. Upload share i to a new server
5. Update the inode with the new share URL
6. Propagate inode changes up the directory tree
7. Publish updated root event

Repair is expensive (requires fetching k full shares), but occurs only on failure.

---

## 12. What Servers Observe

From any individual server's perspective:

- It stores fixed-size encrypted blobs
- Blobs are addressed by hash of ciphertext
- No metadata indicates file names, types, or ownership
- No knowledge of which blobs relate to each other
- Cannot distinguish file data from directory metadata
- Cannot determine total dataset size (blobs may be spread across many servers)

The only information leak is the total storage consumed on that server, which provides a lower bound on dataset size but reveals nothing about structure.

---

## 13. Lifecycle Summary

### 13.1 Upload (Put Once)

1. Pad file to block boundary
2. Encrypt each block with derived key
3. Erasure-code each block into n shares
4. Upload shares to n distinct servers
5. Construct inode containing share locations
6. Recursively upload inode and update directory chain
7. Publish new root event

### 13.2 Maintain (Ongoing)

1. Steward periodically challenges shares
2. On failure detection, steward initiates repair
3. Manifests updated with new server locations
4. Root event updated if structure changes

### 13.3 Read (Local Cache)

1. Check local cache for file
2. If missing: traverse from root, fetch inodes, fetch k shares per block
3. Decode, decrypt, reassemble file
4. Cache locally for future access

### 13.4 Delete (Stop Maintaining)

1. Remove file entry from parent directory
2. Propagate directory updates to root
3. Publish new root event
4. Orphaned shares eventually garbage-collected by servers

---

## 14. Future Considerations

- **Payment integration**: Servers require compensation for storage. Integration with Lightning or ecash for per-byte or subscription-based payment.

- **Server discovery**: Automated discovery of new blossom servers when existing ones fail. Could leverage a Nostr-based server registry.

- **Steward delegation**: Threshold signatures or capability tokens to limit steward authority while enabling autonomous repair.

- **Deduplication**: Content-addressed storage naturally deduplicates identical files. Cross-file block-level deduplication could reduce storage for similar files.

- **Proof of Retrievability**: More sophisticated cryptographic proofs (e.g., KZG commitments) could enable efficient batch verification across many blobs.

---

## 15. Conclusion

This design provides a practical architecture for durable, private, personal storage built on existing Nostr and Blossom infrastructure. By combining erasure coding, content addressing, encryption, and a hierarchical namespace, the system achieves:

- Survival of arbitrary server failures (up to n − k)
- Complete privacy from storage providers
- Full recovery from a single secret key
- Autonomous maintenance via a steward service
- Compatibility with "dumb" storage servers

The layered architecture allows independent evolution of each component, and the reliance on immutable, content-addressed blobs simplifies consistency and enables straightforward caching.
