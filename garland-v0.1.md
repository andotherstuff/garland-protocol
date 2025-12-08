# Nostr-Native Distributed Storage System

## A Design for Erasure-Coded, Privacy-Preserving Blob Storage

**Design Document**  
**December 2025**

---

## Abstract

This document describes a distributed storage system built upon Nostr and Blossom infrastructure that provides durable, privacy-preserving storage for immutable blobs through erasure coding across independent servers. The system maintains a hierarchical namespace analogous to a filesystem through content-addressed manifests organized in a Merkle DAG structure. State evolution is tracked via a cryptographically-linked hash chain of commit events, enabling complete auditability and straightforward disaster recovery. The entire dataset-including all historical state-remains recoverable from a single cryptographic key. This design prioritizes user sovereignty: the owner explicitly controls when changes are committed, which servers store their data, and when obsolete data is garbage collected.

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Design Goals](#2-design-goals)
3. [Architecture Overview](#3-architecture-overview)
4. [Block Layer](#4-block-layer)
5. [Erasure Coding Layer](#5-erasure-coding-layer)
6. [Encryption Layer](#6-encryption-layer)
7. [Inode Structure](#7-inode-structure)
8. [Directory Hierarchy](#8-directory-hierarchy)
9. [State Management via Hash Chain](#9-state-management-via-hash-chain)
10. [Single-Key Discovery and Recovery](#10-single-key-discovery-and-recovery)
11. [Transport Layer](#11-transport-layer)
12. [Verification and Availability Checks](#12-verification-and-availability-checks)
13. [Garbage Collection](#13-garbage-collection)
14. [Lifecycle Summary](#14-lifecycle-summary)
15. [Security Analysis](#15-security-analysis)
16. [Future Considerations](#16-future-considerations)
17. [Conclusion](#17-conclusion)

---

## 1. Introduction

The proliferation of cloud storage services has created a fundamental tension between convenience and sovereignty. Users gain seamless synchronization across devices but surrender control over their data to third parties who may inspect it, monetize it, lose it, or deny access to it. The alternative-self-hosted infrastructure-demands technical expertise and ongoing maintenance that most users cannot provide.

This system addresses a specific need: reliable long-term storage of personal data across unreliable infrastructure, with complete privacy from storage providers and full recoverability from a single secret. The design assumes that individual storage providers may disappear without warning, yet data should survive as long as a sufficient subset of providers remains operational.

The architecture leverages two existing protocols. Nostr provides a decentralized identity layer where users control cryptographic keypairs and can publish signed events to any compatible relay. Blossom extends this model to binary data, offering content-addressed blob storage over HTTP with Nostr-based authentication. By combining these protocols with erasure coding and client-side encryption, the system achieves properties that neither protocol provides alone.

The core requirements are as follows. First, durability: the system must tolerate arbitrary server failures up to a configurable threshold without data loss. Second, privacy: storage servers must learn nothing about stored content, file sizes, directory structure, or access patterns. Third, sovereignty: the user must retain complete control over their data, including explicit authority over when changes are committed and when old data is deleted. Fourth, recoverability: the entire dataset, including its complete history, must be recoverable from a single secret key. Fifth, simplicity: storage servers remain minimal in functionality-they store and retrieve opaque blobs, nothing more.

---

## 2. Design Goals

### 2.1 Threat Model

Storage servers are assumed to be honest-but-curious and unreliable. They will store data if compensated or incentivized to do so. They may inspect any data they store, analyzing content, access patterns, and timing. They may disappear without notice, whether due to business failure, legal action, or technical problems. They will not actively corrupt data, since content addressing makes such corruption immediately detectable.

The system explicitly does not protect against a coordinated attack where more than n - k servers simultaneously destroy their shares of a given block. Such an attack requires either widespread collusion or a correlated failure mode affecting the majority of selected servers. Users concerned about this threat should select servers across diverse jurisdictions, operators, and infrastructure providers.

The system also does not protect against compromise of the user's secret key. An attacker with access to the nsec can decrypt all data, forge new commits, and irreversibly delete the dataset by publishing malicious state updates. Key management remains the user's responsibility.

### 2.2 Non-Goals

Several capabilities are explicitly outside the scope of this design.

Mutability of stored blobs is not supported. All blobs are immutable and content-addressed. Modifying a file creates new blobs; the old blobs remain until garbage collected. This immutability simplifies consistency, enables caching, and provides natural versioning.

Multi-user access control is not addressed. This design focuses on single-owner storage where one keypair controls the entire dataset. Sharing files, delegating access, or collaborative editing would require additional mechanisms not specified here.

Real-time synchronization is not a goal. The system optimizes for backup and archival workloads rather than low-latency random access. Changes accumulate locally and are committed in explicit snapshots rather than synchronized continuously.

Automated background maintenance is deferred. While a steward service could handle ongoing verification and repair, this design places that responsibility with the client application. The user must periodically verify data availability and initiate repairs when servers fail.

---

## 3. Architecture Overview

The system organizes functionality into distinct layers, each with a single responsibility. Data flows downward through these layers on write and upward on read.

```
┌─────────────────────────────────────────────────────────────┐
│                    State Layer                              │
│         (hash chain of commits, garbage collection)         │
├─────────────────────────────────────────────────────────────┤
│                   Namespace Layer                           │
│              (paths → inodes, Merkle DAG)                   │
├─────────────────────────────────────────────────────────────┤
│                    Inode Layer                              │
│           (file metadata, block references)                 │
├─────────────────────────────────────────────────────────────┤
│                  Encryption Layer                           │
│        (per-block keys, authenticated encryption)           │
├─────────────────────────────────────────────────────────────┤
│                    Block Layer                              │
│             (fixed-size, padded chunks)                     │
├─────────────────────────────────────────────────────────────┤
│                Erasure Coding Layer                         │
│              (Reed-Solomon k-of-n shares)                   │
├─────────────────────────────────────────────────────────────┤
│                  Transport Layer                            │
│           (Blossom PUT/GET, Nostr events)                   │
└─────────────────────────────────────────────────────────────┘
```

When writing a file, the client divides data into fixed-size blocks, encrypts each block with a derived key, erasure-codes each encrypted block into n shares, and uploads those shares to n distinct Blossom servers. The client then constructs an inode containing the metadata needed to reverse this process, encrypts and stores the inode using the same pipeline, updates the directory hierarchy, and publishes a new commit event to the hash chain.

When reading a file, the client traverses from the current chain head through the directory structure to locate the target inode, fetches any k of the n shares for each block, decodes and decrypts the blocks, and reassembles the original file.

---

## 4. Block Layer

### 4.1 Fixed-Size Blocks

All data entering the system is divided into fixed-size blocks before any cryptographic processing. The block size B is a system parameter, typically 256 KiB (262,144 bytes), though implementations may support alternative sizes for specific use cases.

For a file of size S bytes, the number of blocks is:

```
N_blocks = ⌈S / B⌉
```

The final block is padded to exactly B bytes using a length-prefixed padding scheme. The first two bytes of each block encode the actual content length as a big-endian 16-bit unsigned integer, followed by the content bytes, followed by zero bytes to fill the block:

```
[content_length: u16_be][content: content_length bytes][padding: zeros]
```

This scheme enables unambiguous removal of padding during reconstruction. For the final block of a file, content_length contains `S mod B` (or B if S is an exact multiple). For non-final blocks, content_length equals B - 2, and the two-byte overhead slightly reduces effective capacity.

### 4.2 Privacy Through Uniformity

The decision to use fixed-size blocks with padding is primarily motivated by privacy rather than efficiency. When all stored blobs are exactly the same size, external observers cannot perform traffic analysis based on blob dimensions.

Without uniform sizing, an adversary observing uploads could distinguish small files from chunks of large files based on byte counts. They could infer file types from characteristic size patterns-a 4.7 GB blob likely represents a DVD image, while a 25 MB blob with specific dimensions suggests a high-resolution photograph. They could correlate related blobs by noticing that blobs uploaded together have sizes summing to a plausible file size. They could identify whether a blob contains user data or system metadata based on typical metadata sizes.

With uniform blocks, all stored blobs appear identical in size. A 100-byte text file produces the same 256 KiB blob as a chunk of a multi-gigabyte video. Directory metadata, file inodes, and actual content are indistinguishable. The only information leaked is the count of blocks, which provides a loose upper bound on total data volume but reveals nothing about how that volume is distributed across files.

This uniformity has costs. Small files incur substantial padding overhead-a 1 KiB file stored in a 256 KiB block wastes 99.6% of the space, and after erasure coding with overhead factor 1.5x, that 1 KiB file consumes 384 KiB of storage across servers. This design accepts that tradeoff. Systems requiring efficient small-file storage should consider alternative approaches, but such optimizations necessarily leak information about file sizes.

---

## 5. Erasure Coding Layer

### 5.1 Reed-Solomon Coding

Each encrypted block undergoes erasure coding to provide redundancy across multiple storage servers. The system employs Reed-Solomon codes, which belong to the family of Maximum Distance Separable (MDS) codes-they achieve the theoretical optimum for storage efficiency at any given fault tolerance level.

A Reed-Solomon (n, k) code transforms k source symbols into n encoded symbols such that any k of the n symbols suffice to reconstruct the original data. The system can tolerate the loss of any n - k symbols, whether from server failures, network partitions, or data corruption.

The mathematical foundation rests on arithmetic in a Galois Field. This implementation uses GF(2^8), the field with 256 elements corresponding to byte values 0-255. Field elements are represented as polynomials over GF(2) with degree less than 8, and the field is constructed using the irreducible polynomial:

```
p(x) = x⁸ + x⁴ + x³ + x² + 1
```

Addition in GF(2^8) is simply XOR of byte values. Multiplication is more complex but can be implemented efficiently using precomputed logarithm tables. For elements a and b with a,b ≠ 0:

```
a × b = gf_exp[(gf_log[a] + gf_log[b]) mod 255]
```

where gf_log and gf_exp are 256-element lookup tables computed once at initialization using a generator element (typically α = 2).

### 5.2 Encoding Process

Encoding treats each byte position across the k source blocks as coefficients of a polynomial. For byte position i, let b₀, b₁, ..., b_{k-1} be the bytes at position i in each of the k source blocks. These define a polynomial:

```
P(x) = b₀ + b₁x + b₂x² + ... + b_{k-1}x^{k-1}
```

The n encoded shares contain the evaluations of P(x) at n distinct points. Using a systematic encoding where the first k shares contain the original data, the evaluation points are chosen such that P(αⁱ) for i = 0, 1, ..., k-1 reproduces the original bytes (α⁰ = 1, so P(1) = b₀ + b₁ + ... + b_{k-1} requires specific construction).

In practice, encoding multiplies the source vector by a k × n generator matrix GM derived from a Vandermonde matrix. The entry at row i, column j is α^{ij}. For systematic encoding, this matrix is transformed so that its first k columns form the identity matrix:

```
GM_systematic = V_{k,k}⁻¹ × V_{k,n}
```

The resulting encoded shares consist of the k original blocks (unchanged) followed by n - k parity blocks.

### 5.3 Decoding Process

Erasure decoding exploits the key property that erasure locations are known-we know which servers failed, we simply don't have their data. This differs from error correction, where corrupted symbols must first be identified.

Given any k received shares, reconstruction proceeds as follows. Form a k × k matrix by selecting the columns of GM corresponding to the received shares. This submatrix is guaranteed to be invertible due to the MDS property. Compute its inverse. Multiply the received shares by this inverse to obtain the original source blocks.

The computational complexity of classical matrix-based decoding is O(k³) for the matrix inversion plus O(k²) for the matrix-vector multiplication. For the block sizes and redundancy parameters typical in this system, decoding completes in milliseconds on modern hardware. Implementations requiring higher throughput can employ FFT-based algorithms achieving O(n log n) complexity.

### 5.4 Parameter Selection

The choice of n and k determines the tradeoff between storage overhead, fault tolerance, and operational complexity.

| k | n | Overhead | Tolerance | Servers Required |
|---|---|----------|-----------|------------------|
| 2 | 3 | 1.50× | 1 failure | 3 |
| 3 | 5 | 1.67× | 2 failures | 5 |
| 4 | 6 | 1.50× | 2 failures | 6 |
| 4 | 7 | 1.75× | 3 failures | 7 |
| 6 | 9 | 1.50× | 3 failures | 9 |

For personal storage, a (2, 3) or (3, 5) configuration provides a reasonable balance. The former tolerates one server failure with 50% overhead; the latter tolerates two failures with 67% overhead. Users with access to more servers or heightened durability requirements may choose higher parameters.

The system should store shares from the same block on distinct servers to maximize independence. If two shares land on the same server, that server's failure removes two shares rather than one, reducing effective fault tolerance.

### 5.5 Share Addressing

Each share is content-addressed by the SHA-256 hash of its bytes:

```
share_id = SHA256(share_bytes)
```

Blossom servers store and retrieve shares solely by this identifier. They possess no information about which file, block, or user a share belongs to. The share_id serves as both the storage key and the integrity check-if a server returns data whose hash doesn't match the requested ID, the data is corrupt or fraudulent and must be discarded.

---

## 6. Encryption Layer

### 6.1 Key Hierarchy

Encryption employs a hierarchical key derivation scheme rooted in the user's Nostr identity. This hierarchy enables fine-grained key management while maintaining the single-key recovery property.

```
nsec (Nostr secret key)
  │
  └─► Master Storage Key (derived via HKDF)
        │
        └─► Per-File Key (random, stored encrypted in inode)
              │
              └─► Per-Block Key (derived via HKDF from file key + block index)
```

The master storage key is derived deterministically from the nsec:

```
master_key = HKDF-SHA256(
    IKM = nsec,
    salt = "nostr-storage-v1",
    info = "master-key",
    length = 32
)
```

This derivation is deterministic-the same nsec always produces the same master key-enabling recovery without storing additional secrets.

Each file receives a randomly generated 256-bit key at creation time. This per-file key is stored within the file's inode, encrypted to the master key. Random per-file keys ensure that identical files produce different ciphertexts, preventing content-based correlation.

Per-block keys are derived from the file key to avoid nonce reuse concerns:

```
block_key = HKDF-SHA256(
    IKM = file_key,
    salt = "block-encryption",
    info = block_index_as_u64_be,
    length = 32
)
```

### 6.2 Authenticated Encryption

Each block is encrypted using XChaCha20-Poly1305, an authenticated encryption scheme providing both confidentiality and integrity. This algorithm was selected for several reasons.

XChaCha20-Poly1305 uses a 192-bit nonce, large enough that random generation is safe without coordination. The probability of nonce collision reaches 50% only after approximately 2^96 encryptions with the same key-far beyond any realistic usage. This property simplifies implementation since blocks can use random nonces without tracking which nonces have been used.

The algorithm performs well in software without hardware acceleration. On systems lacking AES-NI instructions, ChaCha20 outperforms AES by a factor of three or more. Since storage systems may run on diverse hardware including mobile devices and low-power servers, software performance matters.

Poly1305 authentication detects any modification to the ciphertext. An attacker who alters even a single bit will cause decryption to fail with overwhelming probability. This integrity protection operates independently of the content-addressing scheme and provides defense in depth.

The encryption process for block i with file key K_f:

```
block_key = HKDF-SHA256(K_f, "block-encryption", i, 32)
nonce = random_bytes(24)
ciphertext = XChaCha20-Poly1305-Encrypt(block_key, nonce, plaintext_block)
encrypted_block = nonce || ciphertext
```

The 24-byte nonce is prepended to the ciphertext so decryption can extract it. The authentication tag (16 bytes) is appended by the AEAD construction. Total overhead per block is 40 bytes (24-byte nonce + 16-byte tag), negligible relative to the 256 KiB block size.

### 6.3 Metadata Encryption

File inodes and directory entries contain sensitive metadata-filenames, sizes, timestamps, and structural relationships. This metadata receives the same encryption treatment as file content.

When storing an inode, the client serializes it to JSON, treats the JSON as file content, and processes it through the same block/encrypt/erasure-code pipeline. The resulting shares are indistinguishable from file data shares. Directory blobs undergo identical processing.

This recursive structure means servers observe only uniform encrypted blocks. They cannot determine whether a block contains a photograph, a text document, a directory listing, or another inode. The type and structure of stored data is completely opaque.

---

## 7. Inode Structure

An inode contains all information necessary to reconstruct a file. After decryption, an inode is a JSON object with the following structure:

```json
{
  "version": 1,
  "type": "file",
  "size": 10485760,
  "created": 1701820800,
  "modified": 1701907200,
  "key": "<base64-encoded encrypted file key>",
  "blocks": [
    {
      "index": 0,
      "hash": "<SHA-256 of plaintext block for integrity verification>",
      "shares": [
        {"id": "<share0_sha256>", "server": "https://blossom1.example.com"},
        {"id": "<share1_sha256>", "server": "https://blossom2.example.com"},
        {"id": "<share2_sha256>", "server": "https://blossom3.example.com"}
      ]
    },
    {
      "index": 1,
      "hash": "<SHA-256 of plaintext block>",
      "shares": [
        {"id": "<share0_sha256>", "server": "https://blossom1.example.com"},
        {"id": "<share1_sha256>", "server": "https://blossom2.example.com"},
        {"id": "<share2_sha256>", "server": "https://blossom3.example.com"}
      ]
    }
  ],
  "erasure": {
    "algorithm": "reed-solomon",
    "k": 2,
    "n": 3,
    "field": "gf256"
  }
}
```

The `key` field contains the per-file encryption key, itself encrypted using NIP-44 to the owner's public key. This double encryption-file content encrypted to the file key, file key encrypted to the owner key-enables potential future extensions where file keys could be shared with other parties without exposing the master key.

The `hash` field in each block entry contains the SHA-256 hash of the plaintext block before encryption. This enables integrity verification after decryption: if the decrypted block's hash doesn't match, either the ciphertext was corrupted, the wrong key was used, or the inode itself is corrupt.

The `shares` array maps share indices to their content addresses and storage locations. During reconstruction, the client attempts to fetch shares in order, stopping once k shares are successfully retrieved.

Inodes themselves are stored as blobs following the identical pipeline. An inode is serialized, padded, encrypted, erasure-coded, and distributed. The resulting structure is referenced by its content hash, forming a node in the Merkle DAG.

---

## 8. Directory Hierarchy

### 8.1 Directories as Encrypted Blobs

A directory is simply a file whose decrypted contents enumerate named entries and their corresponding inode references. After decryption, a directory blob contains:

```json
{
  "version": 1,
  "type": "directory",
  "created": 1701820800,
  "modified": 1701907200,
  "entries": {
    "photos": {
      "type": "directory",
      "inode": "<content hash of photos directory inode blob>"
    },
    "documents": {
      "type": "directory",
      "inode": "<content hash of documents directory inode blob>"
    },
    "notes.txt": {
      "type": "file",
      "inode": "<content hash of notes.txt inode blob>"
    }
  }
}
```

This directory blob is encrypted and stored identically to file inodes-same block size, same encryption, same erasure coding. From a server's perspective, all blobs are indistinguishable.

Entry names are stored within the encrypted blob, invisible to servers. An observer cannot determine how many files exist, what they are named, or how the directory tree is structured. They see only a collection of uniform encrypted blocks.

### 8.2 Merkle DAG Structure

The directory hierarchy forms a Merkle Directed Acyclic Graph (DAG). Each node-whether file inode or directory-is identified by the content hash of its encrypted representation. Parent nodes contain the hashes of their children.

```
                    ┌─────────────────┐
                    │  Root Directory │
                    │   hash: 0xABC   │
                    └────────┬────────┘
                             │
            ┌────────────────┼────────────────┐
            │                │                │
            ▼                ▼                ▼
    ┌───────────────┐ ┌───────────────┐ ┌───────────────┐
    │    photos/    │ │  documents/   │ │   notes.txt   │
    │  hash: 0xDEF  │ │  hash: 0x123  │ │  hash: 0x456  │
    └───────┬───────┘ └───────┬───────┘ └───────────────┘
            │                 │
            ▼                 ▼
    ┌───────────────┐ ┌───────────────┐
    │  image1.jpg   │ │  report.pdf   │
    │  hash: 0x789  │ │  hash: 0xFED  │
    └───────────────┘ └───────────────┘
```

This structure provides several important properties. Any node's hash authenticates its entire subtree-if an attacker modifies any descendant, the hashes will not match during traversal. The structure can be verified incrementally; a client can validate a path from root to a specific file without fetching the entire tree. Unchanged subtrees share storage; updating one file doesn't require re-uploading siblings.

### 8.3 Path Resolution

To resolve a path like `/photos/image1.jpg`, the client:

1. Obtains the root directory hash from the current chain head
2. Fetches and decrypts the root directory blob
3. Looks up "photos" in the entries, obtaining hash 0xDEF
4. Fetches and decrypts the photos directory blob  
5. Looks up "image1.jpg" in the entries, obtaining hash 0x789
6. Fetches and decrypts the image1.jpg inode
7. Uses the inode to fetch, decode, decrypt, and reassemble the file

Each step requires fetching k shares, decoding, and decrypting. The total number of blob fetches equals the path depth plus one (for the file inode). Deep hierarchies incur proportionally more round trips.

---

## 9. State Management via Hash Chain

### 9.1 The Problem with Mutable Pointers

A content-addressed storage system requires at least one mutable pointer to locate the current root. Without such a pointer, clients would need to know the root hash through some out-of-band mechanism, and that hash would change with every update.

A naive approach uses a Nostr replaceable event (kinds 30000-39999) to store the current root hash. The most recent event for a given (kind, pubkey, d-tag) tuple supersedes all previous events. This works but has limitations.

Replaceable events provide no history. Once superseded, the previous root is lost unless the client independently preserved it. There is no audit trail showing when changes occurred or what the previous states were. If two clients simultaneously commit changes, one will silently overwrite the other with no indication of conflict.

Conflict detection is impossible. If device A commits while device B is offline, and then device B commits without fetching A's update, B's commit will reference an outdated parent state. With simple replaceable events, this produces silent data loss-A's changes vanish without warning.

### 9.2 Hash Chain of Commits

This design employs a hash chain of commit events rather than a single replaceable pointer. Each commit references its predecessor, forming a cryptographically-linked sequence analogous to a blockchain or git history.

A commit event has the following structure:

```json
{
  "kind": 30097,
  "pubkey": "<owner's public key>",
  "created_at": 1701907200,
  "tags": [
    ["d", "storage-chain"],
    ["prev", "<event ID of previous commit>"],
    ["root", "<content hash of root directory blob>"],
    ["seq", "42"]
  ],
  "content": "<NIP-44 encrypted payload>",
  "sig": "<Schnorr signature>"
}
```

The `prev` tag contains the event ID of the immediately preceding commit, creating the chain. The `seq` tag provides a monotonically increasing sequence number for quick ordering. The `root` tag contains the content hash of the current root directory blob.

The encrypted `content` field contains additional metadata:

```json
{
  "root_inode": {
    "hash": "<content hash of root directory inode>",
    "shares": [
      {"id": "<share_hash>", "server": "https://blossom1.example.com"},
      {"id": "<share_hash>", "server": "https://blossom2.example.com"},
      {"id": "<share_hash>", "server": "https://blossom3.example.com"}
    ]
  },
  "erasure": {"k": 2, "n": 3},
  "garbage": ["<hash1>", "<hash2>"],
  "message": "Added vacation photos"
}
```

The `garbage` array lists blob hashes that are no longer referenced as of this commit and may be deleted. The optional `message` field allows human-readable commit descriptions.

### 9.3 Commit Process

Creating a new commit follows this sequence:

1. Fetch the current chain head from Nostr relays
2. Verify local changes are based on this head (detect conflicts)
3. Upload all new blobs (file blocks, inodes, directories)
4. Construct the new root directory referencing updated content
5. Upload the new root directory blob
6. Create a commit event with `prev` pointing to the fetched head
7. Sign and publish the commit event to Nostr relays

If step 2 reveals that the local state diverges from the chain head-because another device committed in the interim-the client must reconcile before proceeding. Reconciliation strategies include:

- **Abort**: Discard local changes, fetch remote state, let user redo changes
- **Merge**: If changes affect disjoint subtrees, automatically merge
- **Fork**: Create a branch, defer reconciliation to user

The appropriate strategy depends on the application. For personal backup, aborting with user notification is often sufficient. More sophisticated applications might implement git-like merging.

### 9.4 Snapshot-Based Workflow

The hash chain naturally supports an explicit save model rather than continuous synchronization. Users accumulate changes locally-adding files, modifying documents, reorganizing directories-without network activity. These changes exist only on the local device.

When the user explicitly saves (clicks a button, invokes a command), the client:

1. Collects all pending local changes
2. Uploads the changed blobs
3. Publishes a single commit event encompassing all changes

This batching reduces network traffic, avoids intermediate states, and gives users clear checkpoints. The resulting history shows meaningful snapshots ("Added tax documents for 2024") rather than a stream of micro-changes.

Between saves, the local state may be lost if the device fails. This is acceptable for a backup-oriented system-unsaved changes are analogous to unsaved edits in a document editor. Users who want continuous protection should save frequently.

### 9.5 Chain Traversal and History

The complete history is recoverable by walking the chain backward from the head. Each commit's `prev` tag leads to its predecessor until reaching the genesis commit (which has no `prev` tag or a null value).

```
HEAD ──prev──► Commit N-1 ──prev──► Commit N-2 ──prev──► ... ──prev──► Genesis
```

Clients can implement time-travel functionality: given any historical commit, they can reconstruct the exact filesystem state at that point by using the commit's root hash to traverse the Merkle DAG.

This history has storage implications. Old commits reference old blobs which must be retained for history to remain valid. Users who don't need history can garbage collect aggressively. Users who value history must retain more data. Section 13 discusses garbage collection in detail.

---

## 10. Single-Key Discovery and Recovery

### 10.1 Recovery Process

Disaster recovery requires only the owner's Nostr secret key (nsec). No backup files, no secondary credentials, no trusted third party. The recovery process:

1. **Derive public key**: Compute npub from nsec using secp256k1
2. **Query relays**: Request kind 30097 events with author = npub and d-tag = "storage-chain"
3. **Find chain head**: Identify the event with highest sequence number (or most recent created_at)
4. **Derive master key**: Compute master storage key from nsec via HKDF
5. **Decrypt commit**: Decrypt the commit's content field using NIP-44
6. **Fetch root**: Download k shares of the root directory inode using URLs from the commit
7. **Decode and decrypt**: Erasure-decode and decrypt the root directory
8. **Traverse**: Recursively fetch any desired files through the directory structure

The Nostr relay network serves as the discovery layer. Relays are interchangeable-the client can query any relay that might have stored the owner's events. Since events are signed, their authenticity is verifiable regardless of which relay provides them.

### 10.2 Relay Selection

Recovery reliability depends on commit events being retrievable from at least one relay. Users should publish commits to multiple relays and periodically verify that relays still hold their events.

Relay selection strategies include:

- **Personal relays**: Relays the user operates or trusts, likely to retain events long-term
- **Paid relays**: Commercial relays with retention guarantees
- **Popular public relays**: High availability but may prune old events

The commit events are small (a few kilobytes) and don't grow with dataset size. Storing them across many relays is inexpensive and dramatically improves recovery reliability.

### 10.3 Blob Server Discovery

Commit events contain URLs for the servers storing each blob's shares. If a server disappears, its URL becomes invalid, but the blob can still be reconstructed from surviving shares on other servers.

The system doesn't specify a discovery mechanism for finding new servers. In practice:

- Users manually configure a list of preferred servers
- Users may operate their own Blossom server for guaranteed availability
- Future extensions could use a Nostr-based server registry

If insufficient shares remain available for any blob, that blob is unrecoverable. Users should monitor server health and re-upload shares to replacement servers before reaching this point.

---

## 11. Transport Layer

### 11.1 Blossom Protocol

Blossom servers provide content-addressed blob storage over HTTP, authenticated via Nostr events. The protocol is intentionally minimal-servers store bytes and retrieve bytes, nothing more.

Core endpoints:

| Method | Path | Description |
|--------|------|-------------|
| GET | `/{sha256}` | Retrieve blob by hash |
| HEAD | `/{sha256}` | Check blob existence |
| PUT | `/upload` | Store a new blob |
| DELETE | `/{sha256}` | Remove a blob |
| GET | `/list/{pubkey}` | List blobs uploaded by a pubkey |

The `{sha256}` path component is the lowercase hex-encoded SHA-256 hash of the blob's contents. An optional file extension may be appended (e.g., `/{sha256}.pdf`) for MIME type hinting, but servers identify blobs solely by hash.

### 11.2 Authentication

Write operations (PUT, DELETE) require authentication via a Nostr event included in the Authorization header:

```
Authorization: Nostr <base64-encoded-event>
```

The authorization event has kind 24242 and must include:

```json
{
  "kind": 24242,
  "created_at": 1701907200,
  "tags": [
    ["t", "upload"],
    ["x", "<sha256 of blob being uploaded>"],
    ["expiration", "1701910800"]
  ],
  "content": "Uploading backup data",
  "sig": "<signature>"
}
```

The `t` tag specifies the authorized action: "upload", "delete", or "list". The `x` tag binds the authorization to a specific blob hash, preventing replay attacks. The `expiration` tag limits the authorization's validity window.

Servers verify the signature, confirm the kind is 24242, check that the action matches the `t` tag, validate that the current time is before expiration, and for uploads/deletes, verify the `x` tag matches the blob hash.

### 11.3 Server Responses

Successful upload returns a blob descriptor:

```json
{
  "url": "https://cdn.blossom.example/abc123def456...",
  "sha256": "abc123def456...",
  "size": 262144,
  "type": "application/octet-stream",
  "uploaded": 1701907200
}
```

The URL may differ from the upload endpoint if the server uses a CDN or different domain for retrieval.

GET requests return the raw blob bytes with appropriate headers:

```
Content-Type: application/octet-stream
Content-Length: 262144
X-Content-Sha256: abc123def456...
```

HEAD requests return the same headers without the body, enabling existence checks without downloading content.

### 11.4 Server Interchangeability

Blossom servers are interchangeable and fungible. A blob uploaded to server A can be retrieved from server B if server B also has it. The content hash serves as a universal identifier across all servers.

This interchangeability enables several patterns:

- **Mirroring**: Upload the same blob to multiple servers for redundancy
- **Migration**: Move from one server to another by re-uploading
- **CDN integration**: Servers can replicate blobs to edge locations
- **Opportunistic caching**: Clients can check multiple servers and use whichever responds fastest

The system's erasure coding distributes shares across servers, so migration requires uploading only shares to replacement servers, not the full reconstructed blob.

---

## 12. Verification and Availability Checks

The client periodically verifies that shares remain available. Several approaches exist:

- **HEAD requests**: Query each server for share existence. Simple but reveals access patterns to servers.
- **Range requests**: Request a byte range and verify its hash, sampling without downloading full shares.
- **Probabilistic filters**: Servers could publish bloom filters or similar structures enabling local existence checks without revealing queries. This would improve privacy but is not currently part of the Blossom specification.

When verification detects missing shares, repair proceeds by fetching k surviving shares, reconstructing the block, re-encoding the missing share, and uploading to a replacement server. The inode and directory chain must then be updated to reflect the new share location.

---

## 13. Garbage Collection

### 13.1 The Accumulation Problem

Content-addressed immutable storage naturally accumulates data. Updating a file creates new blobs; the old blobs persist. The directory structure uses copy-on-write semantics, so modifying a deeply nested file creates new blobs for every ancestor directory up to the root. Without cleanup, storage consumption grows monotonically even if the logical dataset size remains constant.

This design places garbage collection responsibility entirely with the client. The system does not automatically delete anything. Users must explicitly choose to delete obsolete data, accepting the tradeoff between storage costs and history preservation.

### 13.2 Reference Tracking

The client maintains knowledge of which blobs are reachable from each commit. A blob is garbage if it's unreachable from any commit the user wishes to preserve.

Computing reachability requires traversing the Merkle DAG from each preserved commit's root. For a given set of root hashes, reachable blobs are:

```
reachable = {}
for root in preserved_roots:
    traverse(root, reachable)

def traverse(hash, reachable):
    if hash in reachable:
        return
    reachable.add(hash)
    blob = fetch_and_decrypt(hash)
    for child_hash in extract_references(blob):
        traverse(child_hash, reachable)
```

Blobs not in the reachable set are candidates for deletion.

### 13.3 Deletion Strategies

Several strategies for garbage collection exist, offering different tradeoffs:

**Keep everything**: Never delete blobs. Storage grows unboundedly, but complete history is preserved. Suitable for archival use cases where history has intrinsic value.

**Keep recent history**: Preserve the last N commits or commits from the last M days. Delete blobs unreachable from this window. Balances storage cost against useful history depth.

**Keep only current**: Preserve only the chain head. Delete all blobs unreachable from the current state. Minimizes storage but loses all history. Recovery options are limited if the current state is corrupted.

**Explicit snapshots**: Mark specific commits as preserved (e.g., monthly snapshots, pre-migration backups). Delete blobs unreachable from any preserved commit.

### 13.4 Deletion Process

To delete garbage blobs:

1. Compute the set of blob hashes to delete
2. For each hash and each server storing a share of that blob:
   - Generate a deletion authorization event
   - Send DELETE request with authorization
3. Update the garbage list in the next commit to reflect completed deletions

The commit's `garbage` field serves as an announcement of intent. It signals to future clients examining history that these blobs were deliberately deleted and should not be considered missing or corrupted.

Deletion authorization uses the same Nostr event mechanism as uploads:

```json
{
  "kind": 24242,
  "tags": [
    ["t", "delete"],
    ["x", "<sha256 of blob to delete>"],
    ["expiration", "1701910800"]
  ],
  "content": "Garbage collection",
  "sig": "<signature>"
}
```

### 13.5 Metadata Event Garbage Collection

The hash chain of commit events also accumulates over time. Old commit events may be pruned from relays to reduce storage, but this requires care.

Safe deletion criteria for commit events:

- The commit's blobs have been garbage collected (no point keeping metadata for deleted data)
- The commit is not the chain head or a preserved snapshot
- Sufficient time has passed that no client might be traversing through it

In practice, commit events are small (kilobytes) and relay storage is cheap. Most users can retain their complete commit history indefinitely. Users with extremely long histories or storage-constrained relays can prune old commits, accepting that history before the pruning point becomes inaccessible.

---

## 14. Lifecycle Summary

### 14.1 Initial Setup

A new user performs one-time setup:

1. Generate or import a Nostr keypair (nsec/npub)
2. Derive the master storage key from nsec
3. Configure preferred Blossom servers
4. Configure preferred Nostr relays
5. Create an empty root directory
6. Publish the genesis commit event

### 14.2 Adding Files

To add a file to the storage system:

1. Read the file content
2. Divide into fixed-size blocks with padding
3. Generate a random per-file encryption key
4. For each block:
   - Derive the block encryption key
   - Encrypt with XChaCha20-Poly1305
   - Erasure-code into n shares
   - Upload shares to n servers
5. Construct the inode with block metadata
6. Encrypt and upload the inode blob
7. Update the parent directory to include the new entry
8. Recursively update ancestors to the root
9. Stage changes for the next commit

### 14.3 Committing Changes

When the user saves:

1. Fetch current chain head from relays
2. Verify local changes are based on this head
3. Upload all staged blobs (files, inodes, directories)
4. Construct commit event with new root and prev reference
5. Sign and publish commit to relays
6. Clear local staged changes

### 14.4 Reading Files

To read a file by path:

1. Fetch current chain head
2. Decrypt commit to obtain root blob location
3. Traverse directory structure to target inode
4. For each block in the inode:
   - Attempt to fetch k shares from listed servers
   - Erasure-decode to recover encrypted block
   - Decrypt with derived block key
5. Concatenate blocks and remove padding
6. Return file contents

### 14.5 Verification and Repair

Periodically, the client should verify data availability:

1. For each blob referenced by the current state:
   - For each share of that blob:
     - Send HEAD request to check existence
     - Optionally, GET and verify hash matches
2. If any blob has fewer than k available shares:
   - Fetch k surviving shares
   - Erasure-decode to recover the block
   - Re-encode to generate missing shares
   - Upload replacement shares to new servers
   - Update inode with new share locations
   - Commit the updated inodes

### 14.6 Garbage Collection

When storage costs warrant cleanup:

1. Decide which commits to preserve
2. Compute reachable blob set from preserved commits
3. Identify unreachable blobs
4. Delete unreachable blobs from servers
5. Optionally delete obsolete commit events from relays
6. Record garbage collection in next commit

---

## 15. Security Analysis

### 15.1 Confidentiality

Storage servers observe only uniformly-sized encrypted blobs. They cannot determine:

- File contents (encrypted with XChaCha20-Poly1305)
- File sizes (obscured by fixed block padding)
- File types (all blocks are indistinguishable)
- Filenames (stored in encrypted directory blobs)
- Directory structure (directories are encrypted like files)
- Relationships between blobs (no plaintext linking)

The encryption is semantic-identical plaintexts produce different ciphertexts due to random per-file keys. Servers cannot detect when users store the same content.

### 15.2 Integrity

Content addressing provides integrity at multiple levels. Share hashes verify individual share integrity. Block hashes (stored in inodes) verify decrypted block integrity. The Merkle DAG structure verifies structural integrity-any modification to any blob changes the root hash.

Poly1305 authentication tags detect ciphertext tampering. Even if an attacker modifies stored ciphertext in a way that produces a valid hash, decryption will fail authentication.

### 15.3 Availability

Erasure coding ensures availability despite server failures. With (k, n) parameters, data survives the loss of any n - k servers. The hash chain ensures commit history survives relay churn as long as at least one relay retains the events.

The system does not provide availability against censorship or targeted attacks where adversaries deliberately destroy more than n - k shares simultaneously.

### 15.4 Authentication

Nostr signatures authenticate all state changes. Only the holder of the nsec can publish valid commit events. Blossom authorization events prevent unauthorized uploads or deletions.

Relays and servers can verify signature validity but cannot forge signatures. A compromised relay could refuse to serve events (availability attack) but cannot produce fake commits (integrity preserved).

### 15.5 Key Compromise

If the nsec is compromised, all security properties fail. The attacker can:

- Decrypt all current and historical data
- Publish malicious commits
- Delete data from servers
- Irrevocably destroy the dataset

Key management is outside this system's scope. Users should employ standard practices: hardware security modules, secure backup procedures, passphrase protection.

---

## 16. Future Considerations

### 16.1 Payment Integration

Storage servers require compensation for resources consumed. Integration with payment systems would enable sustainable server operation.

Possibilities include per-byte pricing with Lightning Network micropayments, subscription models with ecash or traditional payment, and storage markets where servers compete on price and reliability. Payment integration should not compromise privacy-payments should not link to specific blobs or reveal access patterns.

### 16.2 Steward Services

A steward service could handle verification and repair automatically, running continuously without user intervention. This requires delegating sufficient authority to perform repairs without granting full account access.

Potential approaches include capability tokens authorizing specific repair actions, or read-only access combined with user approval for repairs. Steward design involves complex trust tradeoffs and is deferred to future work.

### 16.3 Multi-Device Synchronization

The current design supports multiple devices through the commit chain, but conflict resolution is minimal. Enhanced multi-device support might include automatic merging for non-conflicting changes, three-way merge for file-level conflicts, operational transformation for collaborative editing, and CRDT-based structures for specific data types.

### 16.4 Deduplication

Content addressing naturally deduplicates identical files-they hash to the same blob. Block-level deduplication across files is more complex. Content-defined chunking using rolling hashes (Rabin fingerprinting) could identify common blocks across similar files, reducing storage for versioned documents or near-duplicates.

### 16.5 Proof of Retrievability

More sophisticated cryptographic proofs could enable efficient verification without downloading data. Proof of Retrievability (PoR) schemes allow servers to prove they hold data by responding to challenges. This could reduce verification bandwidth from O(data size) to O(security parameter).

---

## 17. Conclusion

This design provides a practical architecture for durable, private, personal storage built on existing Nostr and Blossom infrastructure. The layered architecture separates concerns: fixed-size blocks provide privacy through uniformity, erasure coding provides durability through redundancy, authenticated encryption provides confidentiality and integrity, the Merkle DAG provides efficient updates and verification, and the hash chain provides auditable history with conflict detection.

The system achieves its core requirements. Durability is provided through erasure coding-data survives arbitrary server failures up to the configured threshold. Privacy is comprehensive-storage providers learn nothing about content, sizes, structure, or access patterns beyond gross storage volume. Sovereignty is preserved-users control when changes commit and when old data is deleted. Recoverability is complete-the entire dataset and its history can be reconstructed from a single secret key.

The reliance on immutable, content-addressed blobs simplifies consistency and enables straightforward caching. The explicit save model gives users clear checkpoints and avoids the complexity of real-time synchronization. The hash chain provides history, auditability, and conflict detection without requiring trusted timestamps or consensus.

Significant work remains for production deployment. Payment integration, automated maintenance, and enhanced multi-device support are areas for future development. But the core architecture presented here provides a solid foundation for personal data storage that respects user sovereignty while leveraging decentralized infrastructure.

---

## References

1. Nostr Protocol. NIP-01: Basic Protocol Flow Description. https://github.com/nostr-protocol/nips/blob/master/01.md

2. Blossom Protocol. BUD-01: Server Specification. https://github.com/hzrd149/blossom

3. IETF RFC 8439. ChaCha20 and Poly1305 for IETF Protocols. https://tools.ietf.org/html/rfc8439

4. IETF RFC 5869. HMAC-based Extract-and-Expand Key Derivation Function (HKDF). https://tools.ietf.org/html/rfc5869

5. IETF RFC 5510. Reed-Solomon Forward Error Correction (FEC) Schemes. https://tools.ietf.org/html/rfc5510

6. BIP-340. Schnorr Signatures for secp256k1. https://bips.dev/340/

7. Nostr Protocol. NIP-44: Encrypted Payloads (Versioned). https://github.com/nostr-protocol/nips/blob/master/44.md

---

## Appendix A: Notation Reference

| Symbol | Meaning |
|--------|---------|
| B | Block size in bytes (typically 262,144) |
| k | Erasure coding: minimum shares for reconstruction |
| n | Erasure coding: total shares per block |
| nsec | Nostr secret key (32 bytes) |
| npub | Nostr public key (32-byte x-coordinate) |
| GF(2^8) | Galois Field with 256 elements |
| H(x) | SHA-256 hash function |
| HKDF | HMAC-based Key Derivation Function |
| XChaCha20 | Extended-nonce ChaCha20 stream cipher |
| Poly1305 | One-time authenticator MAC |

## Appendix B: Recommended Parameters

**Block size**: 256 KiB (262,144 bytes)  
Provides good balance between padding overhead and chunking granularity.

**Erasure coding**: (k=3, n=5)  
Tolerates 2 server failures with 67% storage overhead. Requires 5 independent servers.

**Encryption**: XChaCha20-Poly1305  
192-bit nonces enable safe random generation. Software performance excellent without hardware acceleration.

**Key derivation**: HKDF-SHA256  
Standard, well-analyzed, widely implemented.

**Commit distribution**: 5+ Nostr relays  
Ensures commit retrievability despite relay failures.

**Verification interval**: Weekly  
Balance between catching failures early and minimizing bandwidth.
