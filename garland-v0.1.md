# Nostr-Native Distributed Storage System

## A Design for Erasure-Coded, Privacy-Preserving Blob Storage

**Design Document**  
**December 2025**

---

## Abstract

This document describes a distributed storage system built upon Nostr and Blossom infrastructure that provides durable, privacy-preserving storage for immutable blobs through erasure coding across independent servers. The system maintains a hierarchical namespace analogous to a filesystem through content-addressed manifests organized in a Merkle DAG structure. State evolution is tracked via a cryptographically-linked hash chain of commit events, enabling complete auditability and straightforward disaster recovery. The entire dataset, including all historical state, remains recoverable from a single cryptographic key. This design prioritizes user sovereignty: the owner explicitly controls when changes are committed, which servers store their data, and when obsolete data is garbage collected.

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
12. [Verification and Repair](#12-verification-and-repair)
13. [Garbage Collection](#13-garbage-collection)
14. [What Servers Observe](#14-what-servers-observe)
15. [Lifecycle Summary](#15-lifecycle-summary)
16. [Security Analysis](#16-security-analysis)
17. [Future Considerations](#17-future-considerations)
18. [Conclusion](#18-conclusion)

---

## 1. Introduction

The proliferation of cloud storage services has created a fundamental tension between convenience and sovereignty. Users gain seamless synchronization across devices but surrender control over their data to third parties who may inspect it, monetize it, lose it, or deny access to it. The alternative, self-hosted infrastructure, demands technical expertise and ongoing maintenance that most users cannot provide.

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
│            (per-block keys, ChaCha20)                       │
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

All data entering the system is divided into fixed-size blocks before any cryptographic processing. The block size B is a system parameter, typically 256 KiB (262,144 bytes), though implementations may support alternative sizes for specific use cases. B refers to the final encrypted block size; the plaintext capacity per block is `B - 44` bytes to accommodate the 12-byte nonce and 32-byte MAC (see Section 6.2).

For a file of size S bytes, the plaintext capacity C = B - 44, and the number of blocks is:

```
C = B - 44  (plaintext capacity per block)
N_blocks = ⌈S / C⌉
```

The final block is padded to exactly C bytes using a length-prefixed padding scheme. Only the final block includes a length prefix: the first four bytes encode the actual content length as a big-endian 32-bit unsigned integer, followed by the content bytes, followed by random padding bytes to fill the block:

```
Non-final blocks: [content: C bytes]
Final block:      [content_length: u32_be][content: content_length bytes][padding: random bytes to C total]
```

This scheme enables unambiguous removal of padding during reconstruction. For the final block, content_length contains `S mod C`. A value of 0 indicates the final block is completely full, meaning the file size is an exact multiple of C. Non-final blocks contain exactly C bytes of content with no overhead.

The padding bytes MUST be randomly generated, not zeros. Random padding avoids known-plaintext at predictable locations within blocks. Since the padding is discarded during reconstruction (the decoder uses content_length to determine where content ends), the random bytes need not be reproducible.

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

This uniformity has costs. Small files incur substantial padding overhead: a 1 KiB file stored in a 256 KiB block wastes 99.6% of the space, and after erasure coding with overhead factor 1.5x, that 1 KiB file consumes 384 KiB of storage across servers. This design accepts that tradeoff. Applications with many small files should consider aggregating them into archives (tar, zip) before storage to reduce overhead while preserving privacy.

---

## 5. Erasure Coding Layer

### 5.1 Reed-Solomon Coding

Each encrypted block undergoes erasure coding to provide redundancy across multiple storage servers. The system employs Reed-Solomon codes over GF(2^8), a finite field with 256 elements convenient for byte-oriented operations. These codes are Maximum Distance Separable (MDS), meaning they achieve the theoretical optimum: any k shares suffice to reconstruct k source symbols, with no wasted redundancy.

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

In practice, encoding multiplies the source vector by a k × n generator matrix derived from a Vandermonde matrix. The computational cost is modest: encoding a 256 KiB block completes in milliseconds.

**Interoperability Requirements**: Two implementations using different Reed-Solomon constructions will produce different shares from identical input, breaking interoperability entirely. All Garland implementations MUST use compatible erasure coding.

The reference implementation is [klauspost/reedsolomon](https://github.com/klauspost/reedsolomon) (Go) with default settings:

- **Field**: GF(2^8)
- **Generator matrix**: Vandermonde-derived (the upper k×k portion is the identity matrix; the lower (n-k)×k portion contains encoding coefficients)
- **Encoding**: Systematic (first k shares are the original data pieces, unchanged)

Compatible implementations:
- **Go**: `klauspost/reedsolomon` with default options
- **Rust**: `reed-solomon-erasure` crate (port of klauspost)

New implementations MUST verify compatibility by generating shares for test vectors and comparing byte-for-byte against the reference. The Garland project will publish official test vectors. Implementations producing different shares from identical (k, n, input) tuples MUST NOT be deployed together.

**Block size constraint**: The block size B MUST be chosen such that B is evenly divisible by k. If the implementation uses a fixed block size that may not divide evenly for all k values, blocks MUST be padded to the next multiple of k bytes before splitting. Recommended (B, k) pairs for 256 KiB nominal block size:

| k | B (bytes) | B/k (bytes per share) |
|---|-----------|----------------------|
| 2 | 262,144 | 131,072 |
| 3 | 261,120 (255 KiB) | 87,040 |
| 4 | 262,144 | 65,536 |
| 5 | 262,140 | 52,428 |
| 6 | 262,144 | 43,690 + 4 bytes padding |

Implementations SHOULD select B to divide evenly by k. When this is impractical, padding the block to the next multiple of k before encoding is acceptable.

### 5.3 Decoding Process

Erasure decoding exploits the key property that erasure locations are known: we know which servers failed, we simply don't have their data. This differs from error correction, where corrupted symbols must first be identified.

Given any k received shares, reconstruction proceeds as follows. Form a k × k matrix by selecting the columns of GM corresponding to the received shares. This submatrix is guaranteed to be invertible due to the MDS property. Compute its inverse. Multiply the received shares by this inverse to obtain the original source blocks.

The computational complexity of classical matrix-based decoding is O(k³) for the matrix inversion plus O(k²) for the matrix-vector multiplication. For the block sizes and redundancy parameters typical in this system, decoding completes in milliseconds on modern hardware. Implementations requiring higher throughput can employ FFT-based algorithms achieving O(n log n) complexity.

### 5.4 Parameter Selection

The choice of n and k determines the tradeoff between storage overhead, fault tolerance, and operational complexity.

| k | n | Overhead | Tolerance | Servers Required |
|---|---|----------|-----------|------------------|
| 1 | 3 | 3.00× | 2 failures | 3 |
| 2 | 3 | 1.50× | 1 failure | 3 |
| 3 | 5 | 1.67× | 2 failures | 5 |
| 4 | 6 | 1.50× | 2 failures | 6 |
| 4 | 7 | 1.75× | 3 failures | 7 |
| 6 | 9 | 1.50× | 3 failures | 9 |

**Simple replication (k=1)**: When k=1, erasure coding degenerates to simple replication where each share is an identical copy of the full encrypted block. Any single server can provide the complete block with no decoding required. This configuration trades storage efficiency (n× overhead) for operational simplicity and maximum fault tolerance (survives n−1 failures). It suits users who prioritize simplicity over storage cost, or who have access to few servers. Note that with k=1, all servers store blobs with identical hashes, enabling potential cross-server correlation; with k>1, each share has a unique hash.

**Erasure coding (k>1)**: For personal storage, (n=3, k=2) or (n=5, k=3) provides a reasonable balance. The former tolerates one server failure with 50% overhead; the latter tolerates two failures with 67% overhead. Users with access to more servers or heightened durability requirements may choose higher parameters.

The system should store shares from the same block on distinct servers to maximize independence. If two shares land on the same server, that server's failure removes two shares rather than one, reducing effective fault tolerance.

### 5.5 Share Addressing

Each share is content-addressed by the SHA-256 hash of its bytes:

```
share_id = SHA256(share_bytes)
```

Blossom servers store and retrieve shares solely by this identifier. They possess no information about which file, block, or user a share belongs to. The share_id serves as both the storage key and the integrity check: if a server returns data whose hash doesn't match the requested ID, the data is corrupt or fraudulent and must be discarded.

---

## 6. Encryption Layer

### 6.1 Key Hierarchy

Encryption employs a hierarchical key derivation scheme rooted in the user's Nostr identity. The user's nsec is always combined with a passphrase (empty string by default) to derive a storage identity, which then derives all storage keys.

```
nsec + passphrase (empty string default)
  │
  └─► Storage nsec (PBKDF2, see Section 6.4)
        │
        └─► Master Key (HKDF)
              │
              ├─► Commit Key (HKDF-Expand)
              │
              ├─► Metadata Key (HKDF-Expand)
              │
              ├─► Per-Blob Auth Key (HKDF-Expand with share_id, see Section 11.2)
              │
              └─► Per-File Key (HKDF-Expand with file_id)
                    │
                    └─► Per-Block Key (HKDF-Expand with block index)
```

The master storage key is derived from the storage nsec (not the raw user nsec):

```
master_key = HKDF-SHA256(
    IKM = storage_nsec,
    salt = None,
    info = "garland-v1:master",
    length = 32
)
```

Per RFC 5869, salt should be independent of IKM; using empty salt is explicitly permitted and avoids any dependency concerns. The storage_nsec already has high entropy from PBKDF2, so the extraction phase primarily provides domain separation via the info string. This derivation is fully deterministic: the same nsec + passphrase always produces the same master key, enabling recovery without storing additional secrets. The storage nsec derivation is described in Section 6.4.

Purpose-specific keys are derived from the master key using HKDF-Expand (no additional salt needed since master_key is already a PRK):

```
commit_key = HKDF-Expand(
    PRK = master_key,
    info = "garland-v1:commit",
    length = 32
)

metadata_key = HKDF-Expand(
    PRK = master_key,
    info = "garland-v1:metadata",
    length = 32
)
```

The commit key encrypts commit event content. The metadata key encrypts inodes and directory blobs. Separating these keys limits the impact of potential key compromise and clarifies the encryption scope.

Each file receives a randomly generated 256-bit `file_id` at creation time. This identifier is stored in plaintext within the inode and used to derive the file's encryption key:

```
file_id = random_bytes(32)  # generated at file creation, stored in inode
file_key = HKDF-Expand(
    PRK = master_key,
    info = "garland-v1:file:" || file_id,
    length = 32
)
```

This derivation provides cryptographic separation between metadata and content. An attacker who compromises `metadata_key` can decrypt inodes and learn file structure (names, sizes, timestamps), but cannot derive `file_key` without `master_key`. The `file_id` in plaintext is meaningless without `master_key`.

**File modification**: When a file is modified, the client creates a new inode with a freshly generated `file_id`. This ensures each file version uses a unique `file_key`, preventing key reuse across versions.

Per-block keys are derived from the file key:

```
block_key = HKDF-Expand(
    PRK = file_key,
    info = "garland-v1:block:" || block_index_as_u64_be,
    length = 32
)
```

### 6.2 Encryption

Each block is encrypted using ChaCha20 with HMAC-SHA256 authentication, following a construction similar to NIP-44. This provides both confidentiality and authentication.

The encryption process for block i with file key K_f:

```
block_key = HKDF-Expand(K_f, "garland-v1:block:" || i, 32)
nonce = random_bytes(12)
ciphertext = ChaCha20(block_key, nonce, plaintext_block)
mac = HMAC-SHA256(block_key, nonce || ciphertext)
encrypted_block = nonce || ciphertext || mac
```

The encrypted block format is:

```
[nonce: 12 bytes][ciphertext: B - 44 bytes][mac: 32 bytes]
```

The block size B (typically 256 KiB) refers to the total encrypted block size, ensuring uniform blob sizes for privacy. The plaintext capacity per block is `B - 44` bytes (262,100 bytes for B = 256 KiB). This 44-byte overhead (12-byte nonce + 32-byte MAC) is 0.017% of the block size.

**Random nonces**: Each block uses a freshly generated random nonce, providing defense-in-depth against implementation bugs that might cause key reuse. Even though per-block keys are unique, random nonces add a safety margin.

**Authentication**: The HMAC authenticates both the nonce and ciphertext, detecting tampering before decryption. During decryption, the client first verifies the MAC; if verification fails, decryption does not proceed. This complements the content-addressing integrity (which verifies after decryption) by catching corruption earlier.

**Decryption process**:

```
nonce = encrypted_block[0:12]
ciphertext = encrypted_block[12:-32]
mac = encrypted_block[-32:]
expected_mac = HMAC-SHA256(block_key, nonce || ciphertext)
if not constant_time_compare(mac, expected_mac):
    reject("authentication failed")
plaintext = ChaCha20(block_key, nonce, ciphertext)
```

### 6.3 Metadata Encryption

File inodes and directory entries contain sensitive metadata: filenames, sizes, timestamps, and structural relationships. The client encrypts this metadata using the metadata key derived from the master key, with the same authenticated encryption scheme as file blocks.

When storing a single-block inode or directory, the client:
1. Serializes the structure to JSON
2. Pads to the plaintext capacity C (B - 44 bytes) with random bytes
3. Generates a random 12-byte nonce
4. Encrypts using ChaCha20 with the metadata key and nonce
5. Computes HMAC-SHA256 over nonce || ciphertext
6. Prepends nonce and appends MAC to form B-byte encrypted block
7. Erasure-codes the encrypted block into n shares
8. Uploads shares to n servers

The nonce is embedded in the encrypted block (identical to file content blocks), not stored separately in the parent reference. To decrypt, the client fetches the shares, reconstructs the block, extracts the nonce from the first 12 bytes, verifies the MAC, and decrypts.

The resulting shares are indistinguishable from file data shares. See Section 14 for detailed privacy analysis.

### 6.4 Storage Identity Derivation

The storage nsec is always derived from the user's nsec combined with a passphrase. This derivation serves two purposes: it separates the storage identity from the user's social Nostr identity, and it enables multiple independent storage buckets via different passphrases.

```
function derive_storage_nsec(nsec: bytes[32], passphrase: string) -> bytes[32]:
    salt = HMAC-SHA256(key = "garland-v1-salt", message = nsec)
    stretched = PBKDF2-HMAC-SHA256(
        passphrase = UTF8(passphrase),
        salt = salt,
        iterations = 210000,
        output_length = 32
    )
    return HMAC-SHA256(key = "garland-v1-nsec", message = nsec || stretched)
```

The derivation uses only primitives present in the Nostr ecosystem (HMAC-SHA256, PBKDF2, secp256k1), avoiding new dependencies. PBKDF2 (Password-Based Key Derivation Function 2) deliberately slows key derivation through repeated hashing, making brute-force attacks expensive. The identity-bound salt prevents rainbow tables across users. The 210,000 iteration count follows OWASP 2023 guidelines for PBKDF2-HMAC-SHA256. The derived output is used directly as a secp256k1 private key.

**Default passphrase**: When no passphrase is specified, the empty string is used. This is not a special case; the derivation runs identically with `passphrase = ""`. The empty-string bucket serves as the default storage location.

**Multiple buckets**: Each passphrase produces a distinct storage identity with independent keys, commit chain, and data:

```
nsec + ""                          →  npub_A  →  Storage bucket A (default)
nsec + "correct horse battery"     →  npub_B  →  Storage bucket B
nsec + "abandon abandon abandon"   →  npub_C  →  Storage bucket C
```

Passphrases should have sufficient entropy to resist brute-force attacks. While PBKDF2 slows down guessing, it cannot compensate for low-entropy passphrases. Short dictionary words like "work" or "photos" are easily guessable. Use multiple random words or a strong generated passphrase.

There is no cryptographic linkage between buckets. An attacker with the nsec can access the empty-passphrase bucket but cannot determine if others exist (plausible deniability). Finding additional buckets requires brute-forcing passphrases through 210,000 PBKDF2 iterations per guess.

**Important**: The derived storage identity SHOULD NOT be used for other Nostr purposes (social posting, direct messages, etc.). Commit events published to relays expose the storage pubkey. If that pubkey appears in other contexts, the storage account becomes linked to those activities, undermining privacy. Treat the storage identity as single-purpose.

**Recovery**: Provide nsec + passphrase, derive storage nsec, then proceed with normal recovery (Section 10). A forgotten passphrase means permanent loss of that bucket; there is no recovery mechanism.

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
  "file_id": "<base64-encoded 32-byte random identifier>",
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

The `file_id` field contains a randomly generated 32-byte identifier used to derive the file's encryption key (see Section 6.1). The file key is derived as `HKDF-Expand(master_key, "garland-v1:file:" || file_id, 32)`. This identifier is stored in plaintext within the encrypted inode; an attacker who compromises only `metadata_key` can read the `file_id` but cannot derive the file key without `master_key`.

The `hash` field in each block entry contains the SHA-256 hash of the plaintext block before encryption. This enables integrity verification after decryption: if the decrypted block's hash doesn't match, either the ciphertext was corrupted, the wrong key was used, or the inode itself is corrupt.

The `shares` array is ordered by share index (0 to n-1). The array position determines the share index, which is required for erasure decoding. During reconstruction, the client fetches shares from their listed servers, tracking which indices were successfully retrieved. Once k shares are obtained, decoding can proceed. Storing share indices in the inode (rather than embedding them in share data) provides better privacy: servers cannot determine a share's position in the erasure scheme.

The client stores inodes as blobs using the same pipeline: serialize, pad, encrypt, erasure-code, and distribute. The resulting structure's content hash forms a node in the Merkle DAG.

### 7.1 Large Inodes

Any inode (file or directory) may exceed the plaintext capacity C when serialized. With (n=5, k=3) erasure coding, each block entry requires approximately 500 bytes for share IDs and server URLs. A file with 500,000 blocks or a directory with thousands of entries could exceed the block size limit.

When an inode exceeds C bytes, it is stored as multiple blocks using the same mechanism as file content:

1. Serialize the inode to JSON
2. Split into blocks of C bytes (padding the final block)
3. Encrypt each block with a key derived from a single `inode_id`
4. Erasure-code and upload each encrypted block
5. The parent reference includes the `inode_id` and block list

A multi-block inode reference in a directory entry:

```json
{
  "photos": {
    "type": "directory",
    "inode_id": "<base64-encoded 32-byte random identifier>",
    "blocks": [
      {
        "index": 0,
        "hash": "<SHA-256 of plaintext block>",
        "shares": [
          {"id": "<share0_sha256>", "server": "https://blossom1.example.com"},
          {"id": "<share1_sha256>", "server": "https://blossom2.example.com"}
        ]
      },
      {
        "index": 1,
        "hash": "<SHA-256 of plaintext block>",
        "shares": [...]
      }
    ]
  }
}
```

The `inode_id` serves the same purpose as `file_id` for file content, enabling deterministic key derivation for multi-block data:

```
inode_key = HKDF-Expand(metadata_key, "garland-v1:inode:" || inode_id, 32)
block_key = HKDF-Expand(inode_key, "garland-v1:block:" || block_index_as_u64_be, 32)
```

Each block is then encrypted with ChaCha20 + HMAC-SHA256 using a random nonce, identical to file content blocks.

For single-block inodes (the common case), the inode is encrypted directly with `metadata_key` and the nonce is embedded in the encrypted block (same format as file content blocks). Implementations should use this simpler approach when the serialized inode fits in one block.

This unified approach means the same chunking mechanism handles large files, large directories, and any future large metadata. Implementations use one code path for all cases.

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
      "inode": "<content hash of photos directory inode blob>",
      "shares": [
        {"id": "<share0_sha256>", "server": "https://blossom1.example.com"},
        {"id": "<share1_sha256>", "server": "https://blossom2.example.com"}
      ]
    },
    "documents": {
      "type": "directory",
      "inode": "<content hash of documents directory inode blob>",
      "shares": [...]
    },
    "notes.txt": {
      "type": "file",
      "inode": "<content hash of notes.txt inode blob>",
      "shares": [...]
    }
  }
}
```

Each entry contains the content hash and share locations for the referenced inode. The `inode` field is the SHA-256 hash of the encrypted inode blob (used for integrity verification). The `shares` array lists where to fetch the erasure-coded shares.

The client encrypts and stores directory blobs identically to file inodes: same block size, same authenticated encryption, same erasure coding. Entry names remain within the encrypted blob, invisible to servers.

### 8.2 Merkle DAG Structure

The directory hierarchy forms a Merkle Directed Acyclic Graph (DAG), a tree-like structure where each node is identified by the cryptographic hash of its contents and parent nodes include the hashes of their children. Any modification to a child changes its hash, which propagates up to the root.

Each node, whether file inode or directory, is identified by the content hash of its encrypted representation.

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

This structure provides several important properties. Any node's hash authenticates its entire subtree: if an attacker modifies any descendant, the hashes will not match during traversal. The structure can be verified incrementally; a client can validate a path from root to a specific file without fetching the entire tree. Unchanged subtrees share storage; updating one file doesn't require re-uploading siblings.

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
  "tags": [],
  "content": "<encrypted payload>",
  "sig": "<Schnorr signature>"
}
```

The commit event has no tags. All metadata is encrypted within the content field. The `created_at` timestamp provides temporal ordering; Nostr relays serve events in reverse chronological order by default, enabling retrieval of recent commits.

The client encrypts the `content` field using ChaCha20 with the commit key and a random nonce, followed by HMAC-SHA256 authentication:

```
nonce = random_bytes(12)
ciphertext = ChaCha20(commit_key, nonce, plaintext)
mac = HMAC-SHA256(commit_key, nonce || ciphertext)
content = base64(nonce || ciphertext || mac)
```

The nonce is prepended to the ciphertext within the base64-encoded content, not stored in a tag.

The decrypted content contains:

```json
{
  "prev": "<event ID of previous commit, or null for genesis>",
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

The `prev` field contains the event ID of the immediately preceding commit, creating the chain. The genesis commit sets `prev` to null. Encrypting `prev` hides the commit chain structure from observers, who see only that commits exist but not how they link together.

The `root_inode` field contains the content hash and share locations for the root directory blob. The `garbage` array lists blob hashes that are no longer referenced as of this commit and may be deleted from storage servers. The optional `message` field allows human-readable commit descriptions.

### 9.2 Commit Process

Creating a new commit follows this sequence:

1. Fetch the current chain head from Nostr relays
2. Verify local changes are based on this head (detect conflicts)
3. Upload all new blobs (file blocks, inodes, directories)
4. Construct the new root directory referencing updated content
5. Upload the new root directory blob
6. Create a commit event with `prev` pointing to the fetched head
7. Sign and publish the commit event to Nostr relays

If step 2 reveals that the local state diverges from the chain head because another device committed in the interim, the client must reconcile before proceeding. Reconciliation strategies include:

- **Abort**: Discard local changes, fetch remote state, let user redo changes
- **Merge**: If changes affect disjoint subtrees, automatically merge
- **Fork**: Create a branch, defer reconciliation to user

The appropriate strategy depends on the application. For personal backup, aborting with user notification is often sufficient. More sophisticated applications might implement git-like merging.

### 9.3 Snapshot-Based Workflow

The hash chain naturally supports an explicit save model rather than continuous synchronization. Users accumulate changes locally (adding files, modifying documents, reorganizing directories) without network activity. These changes exist only on the local device.

When the user explicitly saves (clicks a button, invokes a command), the client:

1. Collects all pending local changes
2. Uploads the changed blobs
3. Publishes a single commit event encompassing all changes

This batching reduces network traffic, avoids intermediate states, and gives users clear checkpoints. The resulting history shows meaningful snapshots ("Added tax documents for 2024") rather than a stream of micro-changes.

Between saves, the local state may be lost if the device fails. This is acceptable for a backup-oriented system: unsaved changes are analogous to unsaved edits in a document editor. Users who want continuous protection should save frequently.

### 9.4 Chain Traversal and History

The complete history is recoverable by walking the chain backward from the head. Each commit's `prev` field (within the encrypted content) leads to its predecessor until reaching the genesis commit (which has `prev: null`).

```
HEAD ──prev──► Commit N-1 ──prev──► Commit N-2 ──prev──► ... ──prev──► Genesis
```

Clients can implement time-travel functionality: given any historical commit, they can reconstruct the exact filesystem state at that point by using the commit's root hash to traverse the Merkle DAG.

This history has storage implications. Old commits reference old blobs which must be retained for history to remain valid. Users who don't need history can garbage collect aggressively. Users who value history must retain more data. Section 13 discusses garbage collection in detail.

### 9.5 Head Discovery and Chain Traversal

The commit chain requires two operations: finding the current head for normal use, and traversing the full chain for recovery or history access.

#### Finding the Chain Head

Nostr relays return events in reverse chronological order by `created_at` timestamp. To find the current chain head, clients query for kind 1097 events with `limit=1`:

```
REQ: ["REQ", <sub_id>, {"kinds": [1097], "authors": [<pubkey>], "limit": 1}]
```

The relay returns the most recent commit event. In normal operation, where commits are created sequentially from a single device or with proper conflict resolution, this is the chain head.

If different relays return different "most recent" events (due to propagation delays or clock skew), clients should fall back to full chain traversal to determine the true head. Fetch all commits, build the chain graph, and identify the canonical head as described below.

#### Full Chain Traversal

For disaster recovery or history reconstruction, clients traverse the complete chain:

1. Query for all kind 1097 events by the owner's pubkey (no limit)
2. Decrypt each commit's content to extract its `prev` field
3. Build an index: `event_id → event` and `prev → event_id`
4. Identify the head: the event whose ID appears in no other event's `prev` field
5. Walk backward via `prev` fields until reaching genesis (the commit with `prev: null`)

Since `prev` is encrypted, chain traversal requires decrypting all commits. This is acceptable because:
- Commits are small (a few hundred bytes each)
- Decryption is fast (ChaCha20 + HMAC verification)
- Commits must be decrypted anyway to access their content
- The privacy benefit (hiding chain structure) outweighs the cost

#### Fork Detection

Forks occur when two commits share the same `prev` value, meaning both claim to follow the same parent. During traversal:

1. If multiple events have the same `prev`, a fork exists
2. The event with the later `created_at` timestamp is the canonical head
3. The other branch may contain commits that need merging or represent conflicting changes

For personal single-device usage, forks are rare. Multi-device deployments should implement merge strategies (Section 9.2).

### 9.6 Metadata Privacy

Commit events are publicly visible on relays. To minimize metadata leakage, all fields except those required by Nostr are encrypted within the `content` field:

- **Prev pointer**: Encrypted. Observers cannot see how commits link together.
- **Root hash**: Encrypted. Observers cannot detect when the filesystem changes or correlate commits with blob uploads.
- **Garbage list**: Encrypted. Observers cannot determine when data is being deleted.
- **Commit message**: Encrypted.

The only plaintext metadata exposed is:
- The `created_at` timestamp (required by Nostr protocol)
- The owner's public key (inherent to Nostr signatures)
- The existence of commits (event count reveals activity frequency)

Observers can count commits and analyze timing patterns from `created_at` timestamps, but cannot determine what changed between commits, how much data each commit affects, or how commits relate to each other. Users concerned about timing analysis can batch commits or add random delays to `created_at` values (within Nostr's tolerance for clock skew).

---

## 10. Single-Key Discovery and Recovery

### 10.1 Recovery Process

Disaster recovery requires the owner's Nostr secret key (nsec) and passphrase (empty string if none was set). No backup files, no secondary credentials, no trusted third party. The recovery process:

1. **Derive storage identity**: Combine nsec + passphrase to derive storage nsec (Section 6.4)
2. **Derive storage npub**: Compute public key from storage nsec using secp256k1
3. **Discover relays**: Use client-configured storage relays (see Section 10.2)
4. **Derive master key**: Compute master storage key from storage nsec via HKDF
5. **Find chain head**: Query relays for kind 1097 events with author = storage npub and limit = 1; the most recent commit by `created_at` is the head
6. **Decrypt commit**: Decrypt the head commit's content field using the commit key derived from master key
7. **Fetch root**: Download k shares of the root directory inode using URLs from the commit
8. **Decode and decrypt**: Erasure-decode and decrypt the root directory
9. **Traverse**: Recursively fetch any desired files through the directory structure

For full history recovery, omit the limit parameter in step 4, fetch all commits, and traverse the chain via encrypted `prev` fields as described in Section 9.5.

The Nostr relay network serves as the discovery layer. Relays are interchangeable: the client can query any relay that might have stored the owner's events. Since events are signed, their authenticity is verifiable regardless of which relay provides them.

### 10.2 Relay Selection

Recovery reliability depends on commit events being retrievable from at least one relay. Users should publish commits to multiple relays and periodically verify that relays still hold their events.

**Storage relay list**: Clients maintain an encrypted list of relays dedicated to storage commits. This list is stored within the storage system itself (as an encrypted blob) and also cached locally. The relay list is independent of the user's social NIP-65 relay list, preventing linkage between storage and social identities.

For initial setup or recovery without a cached relay list, clients use a hardcoded set of well-known public relays to bootstrap. Once the commit chain is located, the encrypted relay list can be retrieved and decrypted for ongoing use.

Relay selection strategies include:

- **Personal relays**: Relays the user operates or trusts, likely to retain events long-term
- **Paid relays**: Commercial relays with retention guarantees
- **Public bootstrap relays**: Used only for initial discovery; storage relays should be explicitly configured

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

Blossom servers provide content-addressed blob storage over HTTP. The protocol is intentionally minimal: servers store bytes and retrieve bytes, nothing more.

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

Some servers require authentication for write operations (PUT, DELETE) via a Nostr event in the Authorization header. Other servers operate openly without authentication.

#### Per-Blob Authentication Keys

Using a single pubkey for all uploads allows servers to correlate blobs to the same owner, undermining privacy. To prevent this, the default authentication mode derives a unique keypair for each blob:

```
blob_auth_privkey = HKDF-Expand(
    PRK = master_key,
    info = "garland-v1:auth:" || share_id,
    length = 32
)
blob_auth_pubkey = secp256k1_pubkey(blob_auth_privkey)
```

The share_id (SHA-256 hash of the blob) is already stored in the inode, so no additional data is needed. The same key can be regenerated for deletion.

When authentication is required:

```
Authorization: Nostr <base64-encoded-event>
```

The authorization event has kind 24242:

```json
{
  "kind": 24242,
  "pubkey": "<per-blob derived pubkey>",
  "created_at": 1701907200,
  "tags": [
    ["t", "upload"],
    ["x", "<sha256 of blob being uploaded>"],
    ["expiration", "1701910800"]
  ],
  "content": "",
  "sig": "<signature from per-blob key>"
}
```

The `t` tag specifies the authorized action: "upload" or "delete". The `x` tag binds the authorization to a specific blob hash. The `expiration` tag limits the authorization's validity window.

With per-blob keys, each blob appears to come from a different user. Servers cannot correlate blobs by pubkey, cannot determine total storage per user, and cannot link uploads across time.

#### Identity Key Mode

For servers requiring a billing relationship or account management, users may opt into identity key mode, where all authorizations use the storage identity pubkey directly. This enables per-user quotas and billing but allows the server to correlate all blobs to the same owner.

Identity key mode is selected per-server in client configuration. Users should prefer per-blob keys for privacy-focused servers and identity keys only where billing integration requires it.

#### Server Verification

Servers verify the signature, confirm the kind is 24242, check that the action matches the `t` tag, validate that the current time is before expiration, and verify the `x` tag matches the blob hash. Servers do not need to know which authentication mode the client uses; they simply verify valid signatures.

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

Blossom servers are interchangeable in that any server can store and serve any blob by its content hash. However, inodes explicitly bind specific server URLs for each share:

```json
{
  "shares": [
    {"id": "<share0_hash>", "server": "https://blossom1.example.com"},
    {"id": "<share1_hash>", "server": "https://blossom2.example.com"}
  ]
}
```

Clients fetch shares from these listed servers. There is no automatic discovery mechanism for finding alternative servers that may also host a given share.

In practice, "interchangeability" means:

- **Flexible fetching**: Clients can choose which k of n listed servers to fetch from
- **Repair via replacement**: Failed servers can be replaced by uploading shares to new servers and updating the inode
- **Migration**: Move from one server to another by re-uploading shares and updating references
- **CDN integration**: Servers can replicate blobs to edge locations transparently

The system does not include automatic discovery of alternative servers hosting a given share.

---

## 12. Verification and Repair

### 12.1 The Verification Service

Data durability requires ongoing verification that shares remain available across storage servers. This verification can be performed by the client application directly, or delegated to a separate steward service that runs independently.

A steward is a process (potentially running on a dedicated server, a home machine, or a cloud instance) that:

1. Periodically reads the owner's current state from the commit chain
2. Challenges each share location to verify data availability
3. Detects failures and initiates repair when shares become unavailable
4. Updates the commit chain with new share locations after repair

The steward requires sufficient credentials to perform these operations. In the simplest model, it holds the owner's nsec (or derived storage nsec if using passphrase protection). More sophisticated deployments might use delegated keys with limited authority, sufficient to read manifests and upload replacement shares but unable to delete data or modify directory structure.

The verification frequency depends on the user's durability requirements and tolerance for data loss. Weekly verification catches most server failures before they cascade. Daily verification provides stronger guarantees at higher bandwidth cost. Users with critical data might verify continuously, while archival users might verify monthly.

### 12.2 Verification Approaches

Several approaches exist for verifying share availability, each with different tradeoffs between simplicity, bandwidth, privacy, and integrity guarantees.

#### Existence Checks via HEAD Requests

The simplest approach queries each server for share existence:

```
HEAD /{share_hash}
```

If the server returns 200 OK, the share exists. If it returns 404 Not Found, the share is missing.

| Aspect | Assessment |
|--------|------------|
| Bandwidth | Minimal: only HTTP headers exchanged |
| Privacy | Poor: servers observe exactly which shares are being verified and when |
| Integrity | None: confirms existence but not correctness; a server could return 200 for corrupted data |
| Implementation | Trivial: standard HTTP |

This approach suits low-threat environments where servers are trusted not to serve corrupted data and privacy from servers is not a concern.

#### Content Verification via Byte Range Requests

A stronger approach downloads a portion of each share and verifies it against known-good data:

```
GET /{share_hash}
Range: bytes=offset-end
```

The verifier selects a random byte range, requests those bytes, and compares them against locally-stored share data or recomputes them from local file copies.

| Aspect | Assessment |
|--------|------------|
| Bandwidth | Moderate: downloads partial share data; configurable via range size |
| Privacy | Poor: servers observe which shares are accessed |
| Integrity | Strong: verifies actual content, not just metadata; random sampling makes undetected corruption probabilistically unlikely |
| Implementation | Moderate: requires local storage of shares or ability to reconstruct them |

For complete integrity verification, the entire share can be downloaded and hashed:

```
H(downloaded_bytes) == share_hash
```

This guarantees the server holds the exact data, at the cost of downloading every byte.

#### Privacy-Preserving Verification via Server Filters

Blossom servers may publish probabilistic data structures (such as fuse filters) listing all blob hashes they store. Clients can query these filters locally without revealing which specific blobs they're checking. Fuse filters are a modern alternative to Bloom filters, offering better space efficiency and query performance while providing the same probabilistic membership testing.

```
GET /filter
→ Returns fuse filter of all stored blob hashes

Client checks: share_hash ∈ filter?
```

| Aspect | Assessment |
|--------|------------|
| Bandwidth | Low: download filter once, check many blobs locally |
| Privacy | Good: server cannot determine which blobs client is verifying |
| Integrity | None: confirms server claims to have the blob; does not verify content |
| Implementation | Requires server support; filter format must be standardized |

This approach can be combined with selective content verification: use filters for routine existence checks, then perform byte-range verification on a random sample or when filters indicate potential issues.

#### Hybrid Verification Strategy

A practical deployment might combine approaches:

1. **Daily**: Download server filters, check all shares exist in filters
2. **Weekly**: Perform HEAD requests for any shares not covered by filters
3. **Monthly**: Download and fully verify a random 1% sample of shares
4. **On suspicion**: Fully verify any share that failed a lighter check

This balances bandwidth, privacy, and integrity while catching most failure modes.

### 12.3 Repair Flow

When verification detects that share i of block b is unavailable or corrupted:

1. **Assess damage**: Count how many shares of block b remain available. If fewer than k shares survive, the block is unrecoverable.

2. **Fetch surviving shares**: Download any k of the surviving shares from their respective servers. Track which share indices were retrieved.

3. **Reconstruct the block**: Apply erasure decoding using the k retrieved shares to recover the original encrypted block.

4. **Regenerate missing share**: Re-encode the block to produce all n shares. Extract share i (and any other missing shares).

5. **Select replacement server**: Choose a new server to host the replacement share. Prefer servers not already storing shares of this block to maintain failure independence.

6. **Upload replacement**: Upload share i to the replacement server, obtaining its URL.

7. **Update inode**: Modify the block's share list to reflect the new server URL. This creates a new inode blob.

8. **Propagate changes**: The modified inode changes its content hash. Update parent directories up to the root.

9. **Commit**: Publish a new commit event with the updated root, referencing the previous commit.

**Local file optimization**: If the client has the original file locally, steps 2-3 can be skipped entirely. Re-encrypt the local block with the same file key and block index (producing identical ciphertext), then re-encode to generate the missing share. This avoids downloading k shares over the network and is significantly faster.

Repair from remote shares is expensive: it requires downloading k full shares (potentially hundreds of kilobytes each) and uploading at least one new share. However, repair occurs only on failure, and early detection prevents cascading failures that could make blocks unrecoverable.

### 12.4 Steward Authority

Currently, a steward requires the full storage nsec to perform repairs. Both Blossom uploads (kind 24242 authorization) and commit events (kind 1097) require signatures from the storage keypair. There is no mechanism for delegated or restricted authority with current Nostr primitives.

This means steward compromise is equivalent to full account compromise. Users must weigh the availability benefits of automated repair against the risk of key exposure. See Section 17.2 for discussion of potential protocol extensions enabling fine-grained delegation.

---

## 13. Garbage Collection

### 13.1 The Accumulation Problem

Content-addressed immutable storage naturally accumulates data. Updating a file creates new blobs; the old blobs persist. The directory structure uses copy-on-write semantics, so modifying a deeply nested file creates new blobs for every ancestor directory up to the root. Without cleanup, storage consumption grows monotonically even if the logical dataset size remains constant.

This design places garbage collection responsibility entirely with the client. The system does not automatically delete anything. Users must explicitly choose to delete obsolete data, accepting the tradeoff between storage costs and history preservation.

### 13.2 Reference Tracking

The client maintains knowledge of which blobs are reachable from each commit. A blob is garbage if it's unreachable from any commit the user wishes to preserve.

Computing reachability requires traversing the Merkle DAG from each preserved commit's root. The traversal handles all blob types uniformly:

**Inode references**: Each reference (in directory entries or commit content) may be single-block (has `inode` or `hash` field plus `shares`) or multi-block (has `inode_id` and `blocks` array). Collect all share IDs from the reference, then fetch and decrypt to traverse the inode's contents.

**File inodes**: Extract `blocks[i].shares[j].id` for all file content shares.

**Directory inodes**: For each entry, collect its inode reference shares, then recursively traverse the child inode.

```
reachable_shares = {}

def collect_inode_ref_shares(ref):
    """Collect shares from a single-block or multi-block inode reference."""
    if ref.blocks:  # multi-block inode
        for block in ref.blocks:
            for share in block.shares:
                reachable_shares.add(share.id)
    else:  # single-block inode (has shares directly)
        for share in ref.shares:
            reachable_shares.add(share.id)

def traverse_from_commit(commit):
    collect_inode_ref_shares(commit.root_inode)
    root = fetch_and_decrypt(commit.root_inode)
    traverse_inode(root)

def traverse_inode(inode):
    if inode.type == "directory":
        for entry in inode.entries.values():
            collect_inode_ref_shares(entry)
            child = fetch_and_decrypt(entry)
            traverse_inode(child)
    elif inode.type == "file":
        for block in inode.blocks:
            for share in block.shares:
                reachable_shares.add(share.id)
```

Shares not in `reachable_shares` are candidates for deletion. This includes old file content, old inodes, and old directory blobs from previous versions.

### 13.3 Incremental Garbage Collection

The `garbage` array in each commit (Section 9.1) lists blobs that became unreachable at that commit. This enables incremental collection without full DAG traversal:

```
def incremental_gc(oldest_commit_to_discard, oldest_commit_to_keep):
    """Delete garbage from commits between discard and keep boundaries."""
    commit = oldest_commit_to_discard
    while commit != oldest_commit_to_keep:
        for blob_hash in commit.garbage:
            delete_all_shares(blob_hash)
        commit = next_commit(commit)  # follow chain forward
```

**Algorithm:**

1. Walk the commit chain forward from the oldest commit you wish to discard
2. At each commit, delete the blobs listed in its `garbage` array
3. Continue until reaching the oldest commit you wish to retain
4. Optionally delete the commit events themselves from relays

This approach:
- Requires no DAG traversal or client-side reachability computation
- Each commit already records exactly what it obsoletes
- Works incrementally as new commits are created
- Deletes garbage in the order it was created

**Example**: To keep only the last 30 days of history, find commits older than 30 days and walk forward through them, deleting each commit's garbage list. Stop at the 30-day boundary.

### 13.4 Retention Strategies

Several strategies for garbage collection exist, offering different tradeoffs:

**Keep everything**: Never delete blobs. Storage grows unboundedly, but complete history is preserved. Suitable for archival use cases where history has intrinsic value.

**Keep recent history**: Preserve the last N commits or commits from the last M days. Delete blobs unreachable from this window. Balances storage cost against useful history depth.

**Keep only current**: Preserve only the chain head. Delete all blobs unreachable from the current state. Minimizes storage but loses all history. Recovery options are limited if the current state is corrupted.

**Explicit snapshots**: Mark specific commits as preserved (e.g., monthly snapshots, pre-migration backups). Delete blobs unreachable from any preserved commit.

### 13.5 Deletion Process

To delete a garbage blob, all n shares must be deleted from their respective servers. Partial deletion leaves the blob reconstructable from surviving shares.

To delete garbage blobs:

1. Compute the set of blob hashes to delete
2. For each blob, look up all n share locations from the inode
3. For each share on each server:
   - Generate a deletion authorization event
   - Send DELETE request with authorization
4. Publish a commit with the `garbage` field listing the deleted blob hashes

The commit's `garbage` field serves as an announcement of intent. It signals to future clients examining history that these blobs were deliberately deleted and should not be considered missing or corrupted. Note that these hashes, while encrypted within the commit, could theoretically be correlated by an adversary who previously observed blob uploads, though this requires both passive observation of uploads and access to decrypted commits.

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

### 13.6 Metadata Event Garbage Collection

The hash chain of commit events also accumulates over time. Old commit events may be pruned from relays to reduce storage, but this requires care.

Safe deletion criteria for commit events:

- The commit's blobs have been garbage collected (no point keeping metadata for deleted data)
- The commit is not the chain head or a preserved snapshot
- Sufficient time has passed that no client might be traversing through it

In practice, commit events are small (kilobytes) and relay storage is cheap. Most users can retain their complete commit history indefinitely. Users with extremely long histories or storage-constrained relays can prune old commits, accepting that history before the pruning point becomes inaccessible.

---

## 14. What Servers Observe

This section provides the consolidated privacy analysis for security review. It details what information storage servers can and cannot learn, forming the basis for evaluating the system's privacy properties.

### 14.1 What Blossom Servers Observe

From any individual Blossom server's perspective:

**Observable:**
- Fixed-size encrypted blobs, all identical in size
- The SHA-256 hash of each blob (used as identifier)
- A unique public key per blob (from per-blob authentication, see Section 11.2)
- Timestamps of upload, access, and deletion requests
- IP addresses and access patterns for requests

**Not observable:**
- Whether a blob contains file data, directory metadata, or an inode
- Original file names, types, or sizes
- Relationships between blobs (which blobs belong to the same file)
- Which blobs belong to the same user (per-blob keys prevent correlation)
- Directory structure or hierarchy depth
- Which blobs are currently "live" versus orphaned from garbage collection
- The plaintext content of any blob
- Total storage per user (each blob has a unique pubkey)

The uniformity of blob sizes is critical. Without it, servers could infer file types from characteristic sizes, correlate related blobs by timing and size patterns, or distinguish small configuration files from chunks of large media files. With uniform sizing, a 100-byte text file produces the same 256 KiB blob as any chunk of a multi-gigabyte video.

Per-blob authentication keys complement uniform sizing: even if a server stores thousands of blobs from one user, it cannot determine they share an owner. Each blob appears to come from a different user. Users who opt into identity key mode (Section 11.2) for billing purposes sacrifice this property on those servers.

### 14.2 What Nostr Relays Observe

Relays storing commit events observe:

**Observable:**
- The public key publishing commits (owner identity or derived storage identity)
- The `created_at` timestamp of each commit
- The encrypted `content` field (opaque ciphertext)
- The total number of commits over time
- Timing patterns of commit activity

**Not observable:**
- The `prev` pointer linking commits (encrypted in content)
- The root hash or any blob references (encrypted in content)
- Commit messages (encrypted in content)
- Garbage collection lists (encrypted in content)
- What changed between commits
- Dataset size or structure
- How commits relate to each other (chain structure hidden)

Observers can count commits and analyze timing but cannot determine whether a commit added one file or a thousand, whether it deleted data via garbage collection, or how commits link together.

### 14.3 Cross-Server Correlation

An adversary controlling multiple servers or observing network traffic might attempt correlation:

**Possible correlations:**
- Uploads to multiple servers at similar times likely belong to the same block
- A user uploading to servers A, B, C is probably using (n=3) erasure coding
- Burst patterns suggest file additions; steady patterns suggest verification

**Mitigations:**
- Upload shares to different servers with random delays
- Use different network paths (Tor, VPN rotation) for different servers
- Avoid predictable verification schedules

**Block reassembly**: If k or more servers collude, they can combine their shares to reconstruct encrypted blocks. However, without the user's key, reassembled blocks remain encrypted and reveal nothing about content. The adversary gains the ability to verify that shares belong together and to detect block-level changes over time, but learns nothing about what the blocks contain.

Even with correlation, the adversary learns only about activity patterns, not content. They might infer "user X added data at time T" but not "user X uploaded family photos."

### 14.4 Information Leak Summary

| Information | Leaked To | Mitigation |
|-------------|-----------|------------|
| Total blob count | Colluding servers | Inherent; use more servers to fragment |
| Activity timing | Servers and relays | Random delays, batching |
| Storage identity | Relays only | Per-blob keys prevent server correlation |
| Number of commits | Relays | Batch changes into fewer commits |
| IP address | Servers and relays | Tor, VPN, proxy rotation |

With per-blob authentication keys, individual Blossom servers cannot determine per-user storage volume. Only colluding servers that combine timing analysis can attempt to correlate blobs, and even then, the link is probabilistic rather than cryptographic.

The system prioritizes content privacy over metadata privacy. What you store is completely hidden; that you store something is partially observable through timing and IP correlation. Users requiring metadata privacy should employ network-level anonymization.

---

## 15. Lifecycle Summary

### 15.1 Initial Setup

A new user performs one-time setup:

1. Generate or import a Nostr keypair (nsec/npub)
2. Choose a passphrase (empty string for default bucket)
3. Derive storage nsec from nsec + passphrase (Section 6.4)
4. Derive master storage key from storage nsec
5. Configure preferred Blossom servers
6. Configure preferred Nostr relays
7. Create an empty root directory
8. Publish the genesis commit event

### 15.2 Adding Files

To add a file to the storage system:

1. Read the file content
2. Divide into fixed-size blocks with padding
3. Generate a random file_id and derive the file encryption key
4. For each block:
   - Derive the block encryption key
   - Encrypt with ChaCha20 + HMAC-SHA256
   - Erasure-code into n shares
   - Upload shares to n servers
5. Construct the inode with file_id and block metadata
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
     - Check existence via HEAD request, server fuse filters, or byte range request
     - Optionally, download and verify full hash matches
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

- File contents (encrypted with ChaCha20)
- File sizes (obscured by fixed block padding)
- File types (all blocks are indistinguishable)
- Filenames (stored in encrypted directory blobs)
- Directory structure (directories are encrypted like files)
- Relationships between blobs (no plaintext linking)

The encryption is semantically secure: identical plaintexts produce different ciphertexts due to random per-file keys and random nonces. Servers cannot detect when users store the same content.

### 16.2 Integrity

Content addressing provides integrity at multiple levels. Share hashes verify individual share integrity. Block hashes (stored in inodes) verify decrypted block integrity. The Merkle DAG structure verifies structural integrity: any modification to any blob changes the root hash.

Content addressing detects ciphertext tampering. If an attacker modifies stored data, the SHA-256 hash will not match the share ID, and the data will be rejected before decryption is attempted.

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

Possibilities include per-byte pricing with Lightning Network micropayments, subscription models with ecash or traditional payment, and storage markets where servers compete on price and reliability. Payment integration should not compromise privacy: payments should not link to specific blobs or reveal access patterns.

### 17.2 Delegated Steward Authority

Fine-grained steward permissions would require protocol extensions not currently available in Nostr/Blossom:

**Blossom capability tokens**: Servers could accept upload authorization from a delegated key pre-authorized by the owner. The owner signs a capability grant: "pubkey X may upload blobs on my behalf until time T". Servers verify the grant chain rather than requiring direct owner signatures.

**Repair-only commit events**: A new event kind for repair commits, signed by a steward key that the owner has authorized via a delegation event. These commits could only modify share URLs, not directory structure or content.

**Separated key hierarchy**: Derive a "repair key" from the master key that can decrypt manifests and re-encode shares, but cannot access file content encryption keys. This limits what a compromised steward can read.

These extensions would enable a steward that can verify and repair without being able to read file contents, delete data, or modify structure, limiting compromise impact to storage cost rather than data loss.

### 17.3 Multi-Device Synchronization

The current design supports multiple devices through the commit chain, but conflict resolution is minimal. Enhanced multi-device support might include automatic merging for non-conflicting changes, three-way merge for file-level conflicts, operational transformation for collaborative editing, and CRDT-based structures for specific data types.

### 17.4 Deduplication

The current design prioritizes semantic security over deduplication. Random per-file keys ensure identical plaintexts produce different ciphertexts, preventing servers from detecting duplicate content—both across users and within a single user's storage. Deduplication is not supported.

Future designs could explore deterministic encryption schemes that enable deduplication while preserving some privacy properties, or content-defined chunking using rolling hashes (Rabin fingerprinting) to identify common blocks across similar files. However, these approaches involve privacy tradeoffs not addressed in this specification.

### 17.5 Proof of Retrievability

More sophisticated cryptographic proofs could enable efficient verification without downloading data. Proof of Retrievability (PoR) schemes allow servers to prove they hold data by responding to challenges. This could reduce verification bandwidth from O(data size) to O(security parameter).

### 17.6 Key Commitment

ChaCha20 (like most stream ciphers) lacks key commitment: an adversary could theoretically construct ciphertext that decrypts to different valid plaintexts under different keys. For single-user storage this is not exploitable, but future multi-user extensions or partial key leakage scenarios might benefit from key-committing AEAD constructions.

---

## 18. Conclusion

This design provides a practical architecture for durable, private, personal storage built on existing Nostr and Blossom infrastructure. The layered architecture separates concerns: fixed-size blocks provide privacy through uniformity, erasure coding provides durability through redundancy, encryption provides confidentiality, content addressing provides integrity, the Merkle DAG provides efficient updates and verification, and the hash chain provides auditable history with conflict detection.

The system achieves its core requirements. Durability is provided through erasure coding: data survives arbitrary server failures up to the configured threshold. Privacy is comprehensive: storage providers learn nothing about content, sizes, structure, or access patterns beyond gross storage volume. Sovereignty is preserved: users control when changes commit and when old data is deleted. Recoverability is complete: the entire dataset and its history can be reconstructed from a single secret key.

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

7. IETF RFC 5869. HMAC-based Extract-and-Expand Key Derivation Function (HKDF). https://tools.ietf.org/html/rfc5869

8. IETF RFC 5510. Reed-Solomon Forward Error Correction (FEC) Schemes. https://tools.ietf.org/html/rfc5510

9. BIP-340. Schnorr Signatures for secp256k1. https://bips.dev/340/

10. IETF RFC 2898. PKCS #5: Password-Based Cryptography Specification Version 2.0. https://tools.ietf.org/html/rfc2898

11. BIP-39. Mnemonic code for generating deterministic keys. https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki

---

## Appendix: Recommended Parameters

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Block size (B) | 256 KiB | Balance between padding overhead and chunking granularity |
| Plaintext capacity (C) | B - 44 bytes | Reserves space for 12-byte nonce + 32-byte MAC |
| Erasure coding | (n=5, k=3) | Tolerates 2 failures with 67% overhead |
| Encryption | ChaCha20 + HMAC-SHA256 | NIP-44 aligned, authenticated encryption |
| Key derivation | HKDF-SHA256 | Standard, widely implemented |
| Commit relays | 5+ | Ensures retrievability despite relay failures |
| Verification | Weekly | Balances failure detection and bandwidth |
| Passphrase KDF | PBKDF2, 210k iterations | OWASP 2023 aligned, ~0.5-1s derivation |
