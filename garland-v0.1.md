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
11. [Passphrase-Protected Storage Identities](#11-passphrase-protected-storage-identities)
12. [Transport Layer](#12-transport-layer)
13. [Verification and Availability Checks](#13-verification-and-availability-checks)
14. [Garbage Collection](#14-garbage-collection)
15. [Lifecycle Summary](#15-lifecycle-summary)
16. [Security Analysis](#16-security-analysis)
17. [Future Considerations](#17-future-considerations)
18. [Conclusion](#18-conclusion)

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

The final block is padded to exactly B bytes using a length-prefixed padding scheme. Only the final block includes a length prefix: the first four bytes encode the actual content length as a big-endian 32-bit unsigned integer, followed by the content bytes, followed by zero bytes to fill the block:

```
Non-final blocks: [content: B bytes]
Final block:      [content_length: u32_be][content: content_length bytes][padding: zeros]
```

This scheme enables unambiguous removal of padding during reconstruction. For the final block, content_length contains `S mod B` (or B if S is an exact multiple of B). Non-final blocks contain exactly B bytes of content with no overhead.

### 4.2 Privacy Through Uniformity

The decision to use fixed-size blocks with padding is primarily motivated by privacy rather than efficiency. When all stored blobs are exactly the same size, external observers cannot perform traffic analysis based on blob dimensions.

Without uniform sizing, an adversary observing uploads could distinguish small files from chunks of large files based on byte counts. They could infer file types from characteristic size patterns-a 4.7 GB blob likely represents a DVD image, while a 25 MB blob with specific dimensions suggests a high-resolution photograph. They could correlate related blobs by noticing that blobs uploaded together have sizes summing to a plausible file size. They could identify whether a blob contains user data or system metadata based on typical metadata sizes.

With uniform blocks, all stored blobs appear identical in size. A 100-byte text file produces the same 256 KiB blob as a chunk of a multi-gigabyte video. Directory metadata, file inodes, and actual content are indistinguishable.

The only information leaked is the count of blocks. An observer watching a specific server sees how many shares that server stores for a given user. Across all n servers, this reveals the total block count. From block count, an observer can infer:

- **Total data volume**: block_count × block_size gives an upper bound on stored data
- **Activity over time**: watching block count changes reveals when data is added or garbage collected
- **Relative dataset size**: comparing users shows who stores more data

However, block count does not reveal:
- How many files exist (one file may span many blocks, many files may fit in one block)
- File sizes (indistinguishable from padding)
- Directory structure depth or breadth
- What fraction is user data vs. metadata

This uniformity has costs. Small files incur substantial padding overhead-a 1 KiB file stored in a 256 KiB block wastes 99.6% of the space, and after erasure coding with overhead factor 1.5x, that 1 KiB file consumes 384 KiB of storage across servers. This design accepts that tradeoff. Systems requiring efficient small-file storage should consider alternative approaches, but such optimizations necessarily leak information about file sizes.

---

## 5. Erasure Coding Layer

### 5.1 Reed-Solomon Coding

Each encrypted block undergoes erasure coding to provide redundancy across multiple storage servers. The system employs Reed-Solomon codes over GF(2^8), which are Maximum Distance Separable (MDS)—achieving optimal storage efficiency for any fault tolerance level.

A Reed-Solomon (n, k) code transforms k source symbols into n encoded symbols such that any k of the n symbols suffice to reconstruct the original data. The system tolerates the loss of any n - k symbols from server failures, network partitions, or data corruption.

### 5.2 Encoding Process

A single encrypted block of size B is encoded as follows:

1. **Split**: Divide the block into k pieces, each of size B/k bytes
2. **Encode**: Apply Reed-Solomon encoding to produce n shares, each of size B/k bytes
3. **Distribute**: Upload each share to a different server

For example, with (n=5, k=3) and B=256 KiB:
- The 256 KiB block is split into 3 pieces of ~85 KiB each
- These are encoded into 5 shares of ~85 KiB each
- Total storage: 5 × 85 KiB ≈ 427 KiB (1.67× overhead)

The encoding treats each byte position across the k pieces as coefficients of a polynomial. For byte position i, let b₀, b₁, ..., b_{k-1} be the bytes at position i in each piece. These define a polynomial:

```
P(x) = b₀ + b₁x + b₂x² + ... + b_{k-1}x^{k-1}
```

The n shares contain the evaluations of P(x) at n distinct points. Using systematic encoding, the first k shares contain the original k pieces unchanged, followed by n - k parity shares.

In practice, encoding multiplies the source vector by a k × n generator matrix derived from a Vandermonde matrix. The computational cost is modest-encoding a 256 KiB block completes in milliseconds.

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

For personal storage, an (n=3, k=2) or (n=5, k=3) configuration provides a reasonable balance. The former tolerates one server failure with 50% overhead; the latter tolerates two failures with 67% overhead. Users with access to more servers or heightened durability requirements may choose higher parameters.

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
        ├─► Commit Key (derived, for encrypting commit events)
        │
        ├─► Metadata Key (derived, for encrypting inodes and directories)
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

Purpose-specific keys are derived from the master key:

```
commit_key = HKDF-SHA256(
    IKM = master_key,
    salt = "nostr-storage-v1",
    info = "commit-encryption",
    length = 32
)

metadata_key = HKDF-SHA256(
    IKM = master_key,
    salt = "nostr-storage-v1",
    info = "metadata-encryption",
    length = 32
)
```

The commit key encrypts commit event content and sequence number tags. The metadata key encrypts inodes and directory blobs. Separating these keys limits the impact of potential key compromise and clarifies the encryption scope.

Each file receives a randomly generated 256-bit key at creation time. This per-file key is stored within the file's inode, encrypted using XChaCha20-Poly1305 with the metadata key. Random per-file keys ensure that identical files produce different ciphertexts, preventing content-based correlation.

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

File inodes and directory entries contain sensitive metadata-filenames, sizes, timestamps, and structural relationships. This metadata is encrypted using the metadata key derived from the master key.

When storing an inode or directory, the client:
1. Serializes the structure to JSON
2. Pads to the fixed block size (256 KiB)
3. Encrypts using XChaCha20-Poly1305 with the metadata key
4. Erasure-codes the encrypted block into n shares
5. Uploads shares to n servers

The resulting shares are indistinguishable from file data shares. This recursive structure means servers observe only uniform encrypted blocks. They cannot determine whether a block contains a photograph, a text document, a directory listing, or another inode. The type and structure of stored data is completely opaque.

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

The `key` field contains the per-file encryption key, encrypted using XChaCha20-Poly1305 with the metadata key. File content is encrypted to the file key, and the file key is encrypted to the metadata key. This hierarchy enables recovery from a single nsec while keeping file keys isolated.

The `hash` field in each block entry contains the SHA-256 hash of the plaintext block before encryption. This enables integrity verification after decryption: if the decrypted block's hash doesn't match, either the ciphertext was corrupted, the wrong key was used, or the inode itself is corrupt.

The `shares` array is ordered by share index (0 to n-1). The array position determines the share index, which is required for erasure decoding. During reconstruction, the client fetches shares from their listed servers, tracking which indices were successfully retrieved. Once k shares are obtained, decoding can proceed. Storing share indices in the inode (rather than embedding them in share data) provides better privacy-servers cannot determine a share's position in the erasure scheme.

Inodes themselves are stored as blobs following the identical pipeline. An inode is serialized, padded, encrypted, erasure-coded, and distributed. The resulting structure is referenced by its content hash, forming a node in the Merkle DAG.

### 7.1 Large File Inodes

Files with many blocks may produce inodes exceeding the standard block size. With (n=5, k=3) erasure coding, each block entry requires approximately 500 bytes for share IDs and server URLs. A file with 500,000 blocks would generate a ~250 MB inode—far exceeding the 256 KiB block limit.

For files exceeding approximately 500 blocks, the inode uses an indirect block structure:

```json
{
  "version": 1,
  "type": "file",
  "size": 137438953472,
  "indirect": true,
  "block_index": [
    {"hash": "<content hash of block index chunk 0>", "shares": [...]},
    {"hash": "<content hash of block index chunk 1>", "shares": [...]}
  ],
  "erasure": {"algorithm": "reed-solomon", "k": 2, "n": 3}
}
```

Each block index chunk contains an array of block entries, stored as a separate encrypted blob. This bounds inode size regardless of file size, at the cost of one additional fetch per block index chunk during file access.

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

### 9.1 Hash Chain of Commits

A content-addressed storage system requires a mutable pointer to locate the current root. This design uses a hash chain of commit events published as regular (non-replaceable) Nostr events. Each commit references its predecessor, forming a cryptographically-linked sequence analogous to a blockchain or git history. Using non-replaceable events ensures all commits persist on relays, enabling full history traversal and conflict detection.

A commit event has the following structure:

```json
{
  "kind": 1097,
  "pubkey": "<owner's public key>",
  "created_at": 1701907200,
  "tags": [
    ["prev", "<event ID of previous commit>"],
    ["seq", "<encrypted sequence number>"]
  ],
  "content": "<encrypted payload>",
  "sig": "<Schnorr signature>"
}
```

The `prev` tag contains the event ID of the immediately preceding commit, creating the chain. The `seq` tag contains an encrypted sequence number for ordering (see Section 9.5 on metadata privacy).

The encrypted `content` field is encrypted using XChaCha20-Poly1305 with a key derived from the master storage key (see Section 6.1). It contains:

```json
{
  "seq": 42,
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

The `seq` field is the plaintext sequence number (the tag contains it encrypted for ordering without decryption). The `garbage` array lists blob hashes that are no longer referenced as of this commit and may be deleted. The optional `message` field allows human-readable commit descriptions.

### 9.2 Commit Process

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

### 9.3 Snapshot-Based Workflow

The hash chain naturally supports an explicit save model rather than continuous synchronization. Users accumulate changes locally-adding files, modifying documents, reorganizing directories-without network activity. These changes exist only on the local device.

When the user explicitly saves (clicks a button, invokes a command), the client:

1. Collects all pending local changes
2. Uploads the changed blobs
3. Publishes a single commit event encompassing all changes

This batching reduces network traffic, avoids intermediate states, and gives users clear checkpoints. The resulting history shows meaningful snapshots ("Added tax documents for 2024") rather than a stream of micro-changes.

Between saves, the local state may be lost if the device fails. This is acceptable for a backup-oriented system-unsaved changes are analogous to unsaved edits in a document editor. Users who want continuous protection should save frequently.

### 9.4 Chain Traversal and History

The complete history is recoverable by walking the chain backward from the head. Each commit's `prev` tag leads to its predecessor until reaching the genesis commit, which omits the `prev` tag entirely.

```
HEAD ──prev──► Commit N-1 ──prev──► Commit N-2 ──prev──► ... ──prev──► Genesis
```

Clients can implement time-travel functionality: given any historical commit, they can reconstruct the exact filesystem state at that point by using the commit's root hash to traverse the Merkle DAG.

This history has storage implications. Old commits reference old blobs which must be retained for history to remain valid. Users who don't need history can garbage collect aggressively. Users who value history must retain more data. Section 14 discusses garbage collection in detail.

### 9.5 Metadata Privacy

Commit events are publicly visible on relays. To minimize metadata leakage, sensitive fields are encrypted:

- **Sequence number**: The `seq` tag contains the sequence number encrypted with the master key. Clients can decrypt and sort locally. Observers see only opaque ciphertext and cannot determine commit frequency or total count.
- **Root hash**: Stored only in the encrypted content, not as a plaintext tag. Observers cannot detect when the filesystem changes.
- **Commit message**: Stored only in encrypted content.

The only plaintext metadata exposed is:
- The `prev` tag linking to the parent commit (necessary for chain traversal)
- The `created_at` timestamp (required by Nostr protocol)
- The owner's public key (inherent to Nostr signatures)

The `prev` tag reveals the existence of a chain but not its contents. Timing analysis of `created_at` timestamps can reveal activity patterns; users concerned about this can batch commits or add random delays.

---

## 10. Single-Key Discovery and Recovery

### 10.1 Recovery Process

Disaster recovery requires only the owner's Nostr secret key (nsec). No backup files, no secondary credentials, no trusted third party. The recovery process:

1. **Derive public key**: Compute npub from nsec using secp256k1
2. **Discover relays**: Query the user's relay list (NIP-65 outbox model) or use known relays
3. **Query relays**: Request kind 1097 events with author = npub
4. **Derive master key**: Compute master storage key from nsec via HKDF
5. **Find chain head**: Decrypt the `seq` tag of each commit, identify the highest sequence number
6. **Decrypt commit**: Decrypt the commit's content field using the master key
7. **Fetch root**: Download k shares of the root directory inode using URLs from the commit
8. **Decode and decrypt**: Erasure-decode and decrypt the root directory
9. **Traverse**: Recursively fetch any desired files through the directory structure

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

## 11. Passphrase-Protected Storage Identities

### 11.1 Motivation

The base design derives all keys from the user's Nostr secret key (nsec). This provides convenient single-key recovery but creates a single point of compromise: an attacker who obtains the nsec gains complete access to all stored data, past and present.

This section describes an optional extension that derives a separate storage identity from the combination of an nsec and a passphrase. The derived identity is itself a valid Nostr keypair, used transparently throughout the system. This approach requires no changes to the core protocol—it simply changes what nsec is used.

### 11.2 Design Goals

The passphrase extension provides several properties:

**Defense in depth**: Compromise of the nsec alone reveals nothing. The attacker must also obtain the passphrase to derive the storage identity.

**Plausible deniability**: Different passphrases derive different storage identities, each with independent data. There is no cryptographic evidence that additional passphrases exist. A user under duress can reveal a decoy passphrase while keeping sensitive data hidden.

**Multiple independent stores**: A single nsec can manage multiple completely separate storage buckets—one per passphrase. These buckets share no keys, no data, and no visible relationship.

**Implementation simplicity**: The passphrase is processed once at the entry point to derive a storage nsec. All subsequent operations use this derived nsec exactly as the base protocol specifies. No other code paths change.

### 11.3 Cryptographic Primitive Selection

The derivation uses only cryptographic primitives already present in the Nostr ecosystem:

| Primitive | Usage | Already Used In |
|-----------|-------|-----------------|
| HMAC-SHA256 | PRF for PBKDF2 | NIP-44 |
| PBKDF2 | Passphrase stretching | BIP-39 |
| SHA-256 | Hashing | Event IDs, content addressing |
| secp256k1 | Derived keypair | All Nostr signatures |

This design intentionally avoids introducing new primitives such as Argon2 or BLAKE2, even though they offer stronger properties. The rationale:

1. **Reduced attack surface**: Fewer cryptographic assumptions to audit
2. **Implementation availability**: Every Nostr client already has these primitives
3. **Ecosystem consistency**: Matches patterns established by BIP-39 and NIP-44
4. **Hardware wallet compatibility**: PBKDF2 is available on constrained devices

The tradeoff is reduced resistance to GPU-based attacks compared to memory-hard functions. This is acceptable given the compensating factors discussed in Section 11.7.

### 11.4 Key Derivation Specification

The storage nsec is derived from the user's nsec and passphrase as follows:

```
function derive_storage_nsec(nsec: bytes[32], passphrase: string) -> bytes[32]:

    // Step 1: Create identity-bound salt
    // This prevents rainbow tables across different users
    salt = HMAC-SHA256(
        key = "garland-v1-salt",
        message = nsec
    )

    // Step 2: Stretch passphrase with PBKDF2
    // Empty string is valid (the "no passphrase" case)
    stretched = PBKDF2-HMAC-SHA256(
        passphrase = UTF8(passphrase),
        salt = salt,
        iterations = 210000,
        output_length = 32
    )

    // Step 3: Combine nsec and stretched passphrase
    derived_nsec = HMAC-SHA256(
        key = "garland-v1-nsec",
        message = nsec || stretched
    )

    return derived_nsec
```

The derived output is used directly as a secp256k1 private key. The probability of producing an invalid scalar (zero or ≥ curve order) is approximately 2⁻¹²⁸, which is negligible. Implementations may optionally reduce modulo the curve order for defense in depth.

### 11.5 The Empty Passphrase

When no passphrase is provided, the empty string is used:

```
storage_nsec = derive_storage_nsec(user_nsec, "")
```

This is not a special case—the derivation runs identically with `passphrase = ""`. The result is a deterministic storage identity derived from the nsec alone.

The empty-passphrase identity serves as the default or "decoy" storage bucket. Users who never set a passphrase still benefit from the derived identity model, maintaining a clean separation between their social Nostr identity and their storage identity.

### 11.6 Multiple Storage Buckets

Each distinct passphrase produces a distinct storage identity:

```
nsec + ""           →  npub_A  →  Storage bucket A (default/decoy)
nsec + "personal"   →  npub_B  →  Storage bucket B
nsec + "work"       →  npub_C  →  Storage bucket C
nsec + "sensitive"  →  npub_D  →  Storage bucket D
```

Each bucket is completely independent:

- **Different keypairs**: Each has its own npub, visible on relays
- **Separate commit chains**: No `prev` links between buckets
- **Independent servers**: Can use different Blossom servers
- **No cryptographic linkage**: Observing npub_A reveals nothing about npub_B

This enables compartmentalized storage where compromise of one passphrase does not affect others.

### 11.7 Security Analysis

With nsec alone, an attacker can access the empty-passphrase bucket but cannot determine if other buckets exist. Finding additional buckets requires brute-forcing passphrases through PBKDF2 (210,000 iterations per guess). At ~10,000 GPU guesses/second, a passphrase with 80+ bits of entropy remains computationally infeasible to crack.

Under duress, revealing a decoy passphrase provides plausible deniability—there is no cryptographic evidence that other buckets exist. Weak passphrases remain vulnerable to dictionary attacks; high-security buckets require strong passphrases.

Side-channel correlation (timing, IP addresses, relay patterns) can link derived identities. Users requiring strong compartmentalization should access different buckets through different network paths.

### 11.8 Design Rationale

The derived-identity approach was chosen over alternatives:

- **Key-hierarchy-only** (same npub, different encryption keys): Weaker deniability since commits remain discoverable; requires protocol changes.
- **Argon2**: Stronger GPU resistance but introduces BLAKE2b, a primitive not used elsewhere in Nostr.
- **Higher iterations**: Possible but trades usability; 210,000 aligns with OWASP 2023 recommendations.

### 11.9 Implementation Notes

**Iteration count**: The value 210,000 is based on OWASP 2023 guidelines for PBKDF2-HMAC-SHA256. This should be reviewed periodically and increased as hardware improves.

**Passphrase encoding**: Passphrases are encoded as UTF-8 before processing. Implementations should normalize Unicode (NFC recommended) to ensure consistent derivation across platforms.

**Caching**: The derived nsec should be cached in memory for the session duration to avoid repeated PBKDF2 computation. It should never be written to persistent storage.

**UI guidance**: Applications should clearly indicate which storage bucket is active and warn users about the implications of passphrase loss. There is no recovery mechanism—a forgotten passphrase means permanent loss of that bucket's data.

### 11.10 Recovery with Passphrase

The recovery process (Section 10.1) is modified as follows:

1. **Obtain credentials**: User provides nsec and passphrase (empty string if none)
2. **Derive storage nsec**: Apply the derivation function from Section 11.4
3. **Derive storage npub**: Compute public key from derived nsec
4. **Query relays**: Request kind 1097 events with author = storage npub
5. **Continue as normal**: Decrypt commits, fetch root, traverse structure

The only change is steps 1-3: deriving the storage identity before querying relays. All subsequent operations are identical to the base protocol.

### 11.11 Trade-offs Summary

| Benefit | Cost |
|---------|------|
| nsec compromise does not expose data | Must remember passphrase |
| Plausible deniability | Passphrase change requires full re-publish |
| Multiple independent stores | Cannot prove ownership across stores |
| No protocol changes | Storage identity ≠ social identity |
| Uses existing primitives | Less GPU-resistant than Argon2 |

This extension is optional. Users who prefer single-key simplicity can use the empty passphrase exclusively, treating the derived identity as their sole storage identity. Users who require defense in depth or deniability can leverage multiple passphrases to compartmentalize their data.

---

## 12. Transport Layer

### 12.1 Blossom Protocol

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

### 12.2 Authentication

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

### 12.3 Server Responses

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

### 12.4 Server Interchangeability

Blossom servers are interchangeable and fungible. A blob uploaded to server A can be retrieved from server B if server B also has it. The content hash serves as a universal identifier across all servers.

This interchangeability enables several patterns:

- **Mirroring**: Upload the same blob to multiple servers for redundancy
- **Migration**: Move from one server to another by re-uploading
- **CDN integration**: Servers can replicate blobs to edge locations
- **Opportunistic caching**: Clients can check multiple servers and use whichever responds fastest

The system's erasure coding distributes shares across servers, so migration requires uploading only shares to replacement servers, not the full reconstructed blob.

---

## 13. Verification and Availability Checks

The client periodically verifies that shares remain available. Several approaches exist:

- **HEAD requests**: Query each server for share existence. Simple but reveals access patterns to servers.
- **Range requests**: Request a byte range from the server and compare against the locally-stored share data. Since the client retains shares locally (or can reconstruct them from local file copies), it can verify server integrity without trusting precomputed hashes.
- **Probabilistic filters**: Servers could publish bloom filters or similar structures enabling local existence checks without revealing queries. This would improve privacy but is not currently part of the Blossom specification.

When verification detects missing or corrupted shares, repair proceeds by fetching k surviving shares, reconstructing the block, re-encoding the missing share, and uploading to a replacement server. The inode and directory chain must then be updated to reflect the new share location.

---

## 14. Garbage Collection

### 14.1 The Accumulation Problem

Content-addressed immutable storage naturally accumulates data. Updating a file creates new blobs; the old blobs persist. The directory structure uses copy-on-write semantics, so modifying a deeply nested file creates new blobs for every ancestor directory up to the root. Without cleanup, storage consumption grows monotonically even if the logical dataset size remains constant.

This design places garbage collection responsibility entirely with the client. The system does not automatically delete anything. Users must explicitly choose to delete obsolete data, accepting the tradeoff between storage costs and history preservation.

### 14.2 Reference Tracking

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

### 14.3 Deletion Strategies

Several strategies for garbage collection exist, offering different tradeoffs:

**Keep everything**: Never delete blobs. Storage grows unboundedly, but complete history is preserved. Suitable for archival use cases where history has intrinsic value.

**Keep recent history**: Preserve the last N commits or commits from the last M days. Delete blobs unreachable from this window. Balances storage cost against useful history depth.

**Keep only current**: Preserve only the chain head. Delete all blobs unreachable from the current state. Minimizes storage but loses all history. Recovery options are limited if the current state is corrupted.

**Explicit snapshots**: Mark specific commits as preserved (e.g., monthly snapshots, pre-migration backups). Delete blobs unreachable from any preserved commit.

### 14.4 Deletion Process

To delete a garbage blob, all n shares must be deleted from their respective servers. Partial deletion leaves the blob reconstructable from surviving shares.

To delete garbage blobs:

1. Compute the set of blob hashes to delete
2. For each blob, look up all n share locations from the inode
3. For each share on each server:
   - Generate a deletion authorization event
   - Send DELETE request with authorization
4. Publish a commit with the `garbage` field listing the deleted blob hashes

The commit's `garbage` field serves as an announcement of intent. It signals to future clients examining history that these blobs were deliberately deleted and should not be considered missing or corrupted. Note that these hashes, while encrypted within the commit, could theoretically be correlated by an adversary who previously observed blob uploads—though this requires both passive observation of uploads and access to decrypted commits.

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

### 14.5 Metadata Event Garbage Collection

The hash chain of commit events also accumulates over time. Old commit events may be pruned from relays to reduce storage, but this requires care.

Safe deletion criteria for commit events:

- The commit's blobs have been garbage collected (no point keeping metadata for deleted data)
- The commit is not the chain head or a preserved snapshot
- Sufficient time has passed that no client might be traversing through it

In practice, commit events are small (kilobytes) and relay storage is cheap. Most users can retain their complete commit history indefinitely. Users with extremely long histories or storage-constrained relays can prune old commits, accepting that history before the pruning point becomes inaccessible.

---

## 15. Lifecycle Summary

### 15.1 Initial Setup

A new user performs one-time setup:

1. Generate or import a Nostr keypair (nsec/npub)
2. Derive the master storage key from nsec
3. Configure preferred Blossom servers
4. Configure preferred Nostr relays
5. Create an empty root directory
6. Publish the genesis commit event

### 15.2 Adding Files

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

### 15.3 Committing Changes

When the user saves:

1. Fetch current chain head from relays
2. Verify local changes are based on this head
3. Upload all staged blobs (files, inodes, directories)
4. Construct commit event with new root and prev reference
5. Sign and publish commit to relays
6. Clear local staged changes

### 15.4 Reading Files

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

### 15.5 Verification and Repair

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

### 15.6 Garbage Collection

When storage costs warrant cleanup:

1. Decide which commits to preserve
2. Compute reachable blob set from preserved commits
3. Identify unreachable blobs
4. Delete unreachable blobs from servers
5. Optionally delete obsolete commit events from relays
6. Record garbage collection in next commit

---

## 16. Security Analysis

### 16.1 Confidentiality

Storage servers observe only uniformly-sized encrypted blobs. They cannot determine:

- File contents (encrypted with XChaCha20-Poly1305)
- File sizes (obscured by fixed block padding)
- File types (all blocks are indistinguishable)
- Filenames (stored in encrypted directory blobs)
- Directory structure (directories are encrypted like files)
- Relationships between blobs (no plaintext linking)

The encryption is semantic-identical plaintexts produce different ciphertexts due to random per-file keys. Servers cannot detect when users store the same content.

### 16.2 Integrity

Content addressing provides integrity at multiple levels. Share hashes verify individual share integrity. Block hashes (stored in inodes) verify decrypted block integrity. The Merkle DAG structure verifies structural integrity-any modification to any blob changes the root hash.

Poly1305 authentication tags detect ciphertext tampering. Even if an attacker modifies stored ciphertext in a way that produces a valid hash, decryption will fail authentication.

### 16.3 Availability

Erasure coding ensures availability despite server failures. With (n, k) parameters, data survives the loss of any n - k servers. The hash chain ensures commit history survives relay churn as long as at least one relay retains the events.

The system does not provide availability against censorship or targeted attacks where adversaries deliberately destroy more than n - k shares simultaneously.

### 16.4 Authentication

Nostr signatures authenticate all state changes. Only the holder of the nsec can publish valid commit events. Blossom authorization events prevent unauthorized uploads or deletions.

Relays and servers can verify signature validity but cannot forge signatures. A compromised relay could refuse to serve events (availability attack) but cannot produce fake commits (integrity preserved).

### 16.5 Key Compromise

If the nsec is compromised, all security properties fail. The attacker can:

- Decrypt all current and historical data
- Publish malicious commits
- Delete data from servers
- Irrevocably destroy the dataset

Key management is outside this system's scope. Users should employ standard practices: hardware security modules, secure backup procedures, passphrase protection.

---

## 17. Future Considerations

### 17.1 Payment Integration

Storage servers require compensation for resources consumed. Integration with payment systems would enable sustainable server operation.

Possibilities include per-byte pricing with Lightning Network micropayments, subscription models with ecash or traditional payment, and storage markets where servers compete on price and reliability. Payment integration should not compromise privacy-payments should not link to specific blobs or reveal access patterns.

### 17.2 Steward Services

A steward service could handle verification and repair automatically, running continuously without user intervention. This requires delegating sufficient authority to perform repairs without granting full account access.

Potential approaches include capability tokens authorizing specific repair actions, or read-only access combined with user approval for repairs. Steward design involves complex trust tradeoffs and is deferred to future work.

### 17.3 Multi-Device Synchronization

The current design supports multiple devices through the commit chain, but conflict resolution is minimal. Enhanced multi-device support might include automatic merging for non-conflicting changes, three-way merge for file-level conflicts, operational transformation for collaborative editing, and CRDT-based structures for specific data types.

### 17.4 Deduplication

Content addressing naturally deduplicates identical files-they hash to the same blob. Block-level deduplication across files is more complex. Content-defined chunking using rolling hashes (Rabin fingerprinting) could identify common blocks across similar files, reducing storage for versioned documents or near-duplicates.

### 17.5 Proof of Retrievability

More sophisticated cryptographic proofs could enable efficient verification without downloading data. Proof of Retrievability (PoR) schemes allow servers to prove they hold data by responding to challenges. This could reduce verification bandwidth from O(data size) to O(security parameter).

---

## 18. Conclusion

This design provides a practical architecture for durable, private, personal storage built on existing Nostr and Blossom infrastructure. The layered architecture separates concerns: fixed-size blocks provide privacy through uniformity, erasure coding provides durability through redundancy, authenticated encryption provides confidentiality and integrity, the Merkle DAG provides efficient updates and verification, and the hash chain provides auditable history with conflict detection.

The system achieves its core requirements. Durability is provided through erasure coding-data survives arbitrary server failures up to the configured threshold. Privacy is comprehensive-storage providers learn nothing about content, sizes, structure, or access patterns beyond gross storage volume. Sovereignty is preserved-users control when changes commit and when old data is deleted. Recoverability is complete-the entire dataset and its history can be reconstructed from a single secret key.

The reliance on immutable, content-addressed blobs simplifies consistency and enables straightforward caching. The explicit save model gives users clear checkpoints and avoids the complexity of real-time synchronization. The hash chain provides history, auditability, and conflict detection without requiring trusted timestamps or consensus.

Significant work remains for production deployment. Payment integration, automated maintenance, and enhanced multi-device support are areas for future development. But the core architecture presented here provides a solid foundation for personal data storage that respects user sovereignty while leveraging decentralized infrastructure.

---

## References

1. Nostr Protocol. NIP-01: Basic Protocol Flow Description. https://github.com/nostr-protocol/nips/blob/master/01.md

2. Nostr Protocol. NIP-44: Encrypted Payloads (Versioned). https://github.com/nostr-protocol/nips/blob/master/44.md

3. Nostr Protocol. NIP-65: Relay List Metadata. https://github.com/nostr-protocol/nips/blob/master/65.md

4. Blossom Protocol. BUD-01: Server Specification. https://github.com/hzrd149/blossom

5. Nostr Protocol. NIP-B7: Blossom. https://github.com/nostr-protocol/nips/blob/master/B7.md

6. IETF RFC 8439. ChaCha20 and Poly1305 for IETF Protocols. https://tools.ietf.org/html/rfc8439

7. IETF. XChaCha: eXtended-nonce ChaCha and AEAD_XChaCha20_Poly1305. https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03

8. IETF RFC 5869. HMAC-based Extract-and-Expand Key Derivation Function (HKDF). https://tools.ietf.org/html/rfc5869

9. IETF RFC 5510. Reed-Solomon Forward Error Correction (FEC) Schemes. https://tools.ietf.org/html/rfc5510

10. BIP-340. Schnorr Signatures for secp256k1. https://bips.dev/340/

11. IETF RFC 2898. PKCS #5: Password-Based Cryptography Specification Version 2.0. https://tools.ietf.org/html/rfc2898

12. BIP-39. Mnemonic code for generating deterministic keys. https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki

---

## Appendix: Recommended Parameters

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Block size | 256 KiB | Balance between padding overhead and chunking granularity |
| Erasure coding | (n=5, k=3) | Tolerates 2 failures with 67% overhead |
| Encryption | XChaCha20-Poly1305 | Safe random nonces, excellent software performance |
| Key derivation | HKDF-SHA256 | Standard, widely implemented |
| Commit relays | 5+ | Ensures retrievability despite relay failures |
| Verification | Weekly | Balances failure detection and bandwidth |
| Passphrase KDF | PBKDF2, 210k iterations | OWASP 2023 aligned, ~0.5-1s derivation |
