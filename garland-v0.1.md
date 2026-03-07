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

### 3.1 Serialization and Wire Formats

All JSON structures in this protocol (inodes, directory entries, commit content) MUST be serialized using RFC 8785 JSON Canonicalization Scheme (JCS) before hashing, signing, or encrypting them. Deterministic serialization is required for content-addressing: two implementations encoding the same logical structure must produce identical bytes.

Implementations MUST NOT rely on insertion order, runtime hash map ordering, platform-specific floating point formatting, ad hoc whitespace rules, or any other non-canonical JSON behavior. Object member ordering, string escaping, Unicode handling, and number rendering MUST follow RFC 8785 exactly.

**Encoding conventions:**
- **SHA-256 hashes** (share IDs, content hashes): lowercase hex-encoded strings (64 characters)
- **Binary data** (file_id, inode_id, nonces): standard base64 with padding (RFC 4648 Section 4)
- **Integers in binary fields** (content_length, block_index): big-endian unsigned
- **Integers in JSON**: decimal (standard JSON number), but values MUST remain within the I-JSON safe integer range `0 <= x <= 2^53 - 1`
- **Strings**: UTF-8

These conventions apply throughout the spec. When examples show `<content hash>` or `<share_hash>`, these are lowercase hex strings. When examples show `<base64-encoded 32-byte ...>`, these use standard base64 with `=` padding.

---

## 4. Block Layer

### 4.1 Fixed-Size Blocks

All data entering the system is divided into fixed-size blocks before any cryptographic processing. The block size B is a system parameter, fixed at 262,144 bytes (256 KiB). B refers to the total encrypted block size; the plaintext frame per block is `C = B - 44` bytes (262,100 bytes) to accommodate the 12-byte nonce and 32-byte MAC (see Section 6.2).

Every block uses a uniform length-prefixed format. The first four bytes of each plaintext frame encode the content length as a big-endian 32-bit unsigned integer, followed by the content bytes, followed by random padding to fill the frame:

```
Every block: [content_length: u32_be][content: content_length bytes][padding: random bytes to C total]
```

The effective content capacity per block is `C_eff = C - 4 = 262,096` bytes. For a file of size S bytes, the number of blocks is:

```
C = B - 44 = 262,100  (plaintext frame per block)
C_eff = C - 4 = 262,096  (content capacity per block, after 4-byte length prefix)
N_blocks = ⌈S / C_eff⌉   (for S > 0; N_blocks = 1 for S = 0)
```

**content_length semantics**: Each block's `content_length` field stores the number of content bytes in that block:

- **Non-final blocks**: `content_length = C_eff` (the block is completely full of content after the 4-byte prefix, with zero padding bytes)
- **Final block where `S mod C_eff > 0`**: `content_length = S mod C_eff`
- **Final block where `S mod C_eff == 0` and `S > 0`**: `content_length = C_eff` (block is full)
- **Empty file (S = 0)**: a single block with `content_length = 0` (4-byte prefix, then C - 4 bytes of random padding)

The uniform format means every block is parsed identically: read 4-byte prefix, extract `content_length` bytes of content, discard the rest as padding. This eliminates the need to distinguish "final" from "non-final" blocks during decoding -- the only special handling is that the last block's `content_length` may be less than `C_eff`.

The 4-byte-per-block overhead is negligible compared to the padding overhead already inherent in fixed-size blocks.

The padding bytes MUST be randomly generated, not zeros. Random padding avoids known-plaintext at predictable locations within blocks. Since the padding is discarded during reconstruction (the decoder reads exactly `content_length` bytes after the prefix), the random bytes need not be reproducible.

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

New implementations MUST verify compatibility by generating shares for test vectors and comparing byte-for-byte against the reference. Implementations producing different shares from identical `(k, n, input)` tuples MUST NOT be deployed together.

**Block size constraint**: The block size B is fixed at 262,144 bytes (256 KiB) regardless of k. This uniformity is required for privacy: if B varied by k, share sizes would reveal the erasure coding parameter to storage servers.

When B is not evenly divisible by k, the encrypted block MUST be padded with zero bytes to the next multiple of k before Reed-Solomon encoding. The padding length is `(k - (B mod k)) mod k`, which is at most `k - 1` bytes. During reconstruction, after erasure decoding and concatenating the k data shares, the decoder truncates the result to exactly B bytes, discarding any RS padding.

| k | B (bytes) | RS pad (bytes) | Share size (bytes) |
|---|-----------|---------------|-------------------|
| 2 | 262,144 | 0 | 131,072 |
| 3 | 262,144 | 2 | 87,382 |
| 4 | 262,144 | 0 | 65,536 |
| 5 | 262,144 | 1 | 52,429 |
| 6 | 262,144 | 2 | 43,691 |

The share size is `(B + pad) / k`. Implementations MUST NOT vary B to avoid RS padding.

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

**Simple replication (k=1)**: When k=1, erasure coding degenerates to simple replication. Each of the n servers stores the same encrypted block bytes. No splitting or parity generation occurs, and any single server can provide the complete block.

This mode is simpler to implement and survives n - 1 server failures, but it leaks one extra fact: colluding servers can detect that identical share hashes represent replicas of the same encrypted block. Users who want the strongest cross-server unlinkability SHOULD prefer k > 1.

Any single server can provide the complete block with no decoding required. This configuration trades storage efficiency (n× overhead) for operational simplicity and maximum fault tolerance (survives n−1 failures). It suits users who prioritize simplicity over storage cost, or who have access to few servers.

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
        └─► PRK (HKDF-Extract)
              │
              └─► Master Key (HKDF-Expand)
                    │
                    ├─► Commit Key (HKDF-Expand)
                    │
                    ├─► Metadata Key (HKDF-Expand)
                    │     │
                    │     └─► Per-Inode Key (HKDF-Expand with inode_id, see Section 7.1)
                    │           │
                    │           └─► Per-Block Key (HKDF-Expand with block index)
                    │
                    ├─► Per-Blob Auth Key (HKDF-Expand with share_id, see Section 11.2)
                    │
                    └─► Per-File Key (HKDF-Expand with file_id)
                          │
                          └─► Per-Block Key (HKDF-Expand with block index)
```

The master storage key is derived from the storage nsec (not the raw user nsec) using the full HKDF (Extract-then-Expand) as defined in RFC 5869:

```
# Step 1: Extract
PRK = HKDF-Extract(
    salt = 0x0000...00 (32 zero bytes),
    IKM = storage_nsec
)

# Step 2: Expand
master_key = HKDF-Expand(
    PRK = PRK,
    info = "garland-v1:master",
    length = 32
)
```

Per RFC 5869 Section 2.2, when salt is not provided, it defaults to a string of HashLen (32 for SHA-256) zero bytes. The storage_nsec already has high entropy from PBKDF2, so the extraction phase primarily provides domain separation. This derivation is fully deterministic: the same nsec + passphrase always produces the same master key, enabling recovery without storing additional secrets. The storage nsec derivation is described in Section 6.4.

Purpose-specific keys are derived from the master key using HKDF-Expand only. The master_key is a 32-byte pseudorandom output of HKDF-Expand, which satisfies HKDF-Expand's input requirement of "a pseudorandom key of at least HashLen octets" (RFC 5869 Section 2.3):

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

Single-block metadata MAY be encrypted directly under `metadata_key` for simplicity. Multi-block metadata derives a per-inode key from `metadata_key` as shown in the diagram and in Section 7.1.

Each file receives a randomly generated 256-bit `file_id` at creation time. This identifier is stored in plaintext within the inode and used to derive the file's encryption key:

```
file_id = random_bytes(32)
file_key = HKDF-Expand(
    PRK = master_key,
    info = "garland-v1:file:" || file_id,
    length = 32
)
```

This derivation provides cryptographic separation between metadata and content. An attacker who compromises `metadata_key` can decrypt inodes and learn file structure, but cannot derive `file_key` without `master_key`. The `file_id` in plaintext is meaningless without `master_key`.

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

Each block is encrypted using ChaCha20 (RFC 8439, IETF variant with 96-bit nonce, initial block counter = 0) with HMAC-SHA256 authentication, following a construction similar to NIP-44. This provides both confidentiality and authentication.

To maintain cryptographic key separation, each block key is split into distinct encryption and authentication sub-keys via HKDF-Expand:

```
block_key = HKDF-Expand(K_f, "garland-v1:block:" || block_index_as_u64_be, 32)
enc_key   = HKDF-Expand(block_key, "garland-v1:enc", 32)
mac_key   = HKDF-Expand(block_key, "garland-v1:mac", 32)
```

The encryption process for block i with file key K_f:

```
block_key = HKDF-Expand(K_f, "garland-v1:block:" || i, 32)
enc_key = HKDF-Expand(block_key, "garland-v1:enc", 32)
mac_key = HKDF-Expand(block_key, "garland-v1:mac", 32)
nonce = random_bytes(12)
ciphertext = ChaCha20(enc_key, nonce, plaintext_block)
mac = HMAC-SHA256(mac_key, nonce || ciphertext)
encrypted_block = nonce || ciphertext || mac
```

The encrypted block format is:

```
[nonce: 12 bytes][ciphertext: B - 44 bytes][mac: 32 bytes]
```

**Key separation**: Deriving separate `enc_key` and `mac_key` from each `block_key` avoids dual-use keying.

**Random nonces**: Each block uses a freshly generated random nonce, providing defense-in-depth against implementation bugs that might cause key reuse.

**Authentication**: The HMAC authenticates both the nonce and ciphertext, detecting tampering before decryption. This complements the content-addressing integrity check by catching corruption earlier.

**Decryption process**:

```
nonce = encrypted_block[0:12]
ciphertext = encrypted_block[12:-32]
mac = encrypted_block[-32:]
enc_key = HKDF-Expand(block_key, "garland-v1:enc", 32)
mac_key = HKDF-Expand(block_key, "garland-v1:mac", 32)
expected_mac = HMAC-SHA256(mac_key, nonce || ciphertext)
if not constant_time_compare(mac, expected_mac):
    reject("authentication failed")
plaintext = ChaCha20(enc_key, nonce, ciphertext)
```

### 6.3 Metadata Encryption

File inodes and directory entries contain sensitive metadata: filenames, sizes, timestamps, and structural relationships. The client encrypts this metadata using the metadata key derived from the master key, with the same authenticated framing model used for file blocks.

When storing a single-block inode or directory, the client:
1. Serializes the structure to RFC 8785 JCS JSON bytes
2. Verifies that the serialized length is at most `C_eff = C - 4` bytes
3. Frames the plaintext exactly as `[content_length: u32_be] || content || random_padding` to total `C = B - 44` bytes, using the same block format as Section 4.1
4. Derives `enc_key = HKDF-Expand(metadata_key, "garland-v1:enc", 32)` and `mac_key = HKDF-Expand(metadata_key, "garland-v1:mac", 32)`
5. Generates a random 12-byte nonce
6. Encrypts using ChaCha20 with `enc_key` and nonce
7. Computes `HMAC-SHA256(mac_key, nonce || ciphertext)`
8. Prepends nonce and appends MAC to form a B-byte encrypted block
9. Erasure-codes the encrypted block into n shares
10. Uploads shares to n servers

The nonce is embedded in the encrypted block, not stored separately in the parent reference. To decrypt, the client fetches the shares, reconstructs the block, extracts the nonce from the first 12 bytes, verifies the MAC, decrypts, then parses the Section 4.1 frame to recover the JSON bytes.

The resulting shares are indistinguishable from file data shares. See Section 14 for detailed privacy analysis.

### 6.4 Storage Identity Derivation

Whenever this protocol derives a secp256k1 private key from pseudorandom bytes, implementations MUST use the following rejection-sampling procedure:

```
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

function derive_secp256k1_scalar(prk: bytes[32], info: bytes) -> bytes[32]:
    counter = 0
    while true:
        candidate = HKDF-Expand(
            PRK = prk,
            info = info || u32_be(counter),
            length = 32
        )
        x = bytes_to_uint256(candidate)
        if 0 < x < SECP256K1_N:
            return candidate
        counter += 1
```

Implementations MUST NOT reduce candidates modulo the curve order.

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
    seed = HMAC-SHA256(key = "garland-v1-nsec", message = nsec || stretched)
    return derive_secp256k1_scalar(seed, "garland-v1:storage-scalar")
```

The derivation uses only primitives present in the Nostr ecosystem (HMAC-SHA256, PBKDF2, secp256k1), avoiding new dependencies. PBKDF2 (Password-Based Key Derivation Function 2) deliberately slows key derivation through repeated hashing, making brute-force attacks expensive. The identity-bound salt prevents rainbow tables across users. The 210,000 iteration count follows OWASP 2023 guidelines for PBKDF2-HMAC-SHA256. The final rejection-sampling step guarantees a valid secp256k1 private key with deterministic behavior across implementations.

**Default passphrase**: When no passphrase is specified, the empty string is used. This is not a special case; the derivation runs identically with `passphrase = ""`. The empty-string bucket serves as the default storage location.

**Multiple buckets**: Each passphrase produces a distinct storage identity with independent keys, commit chain, and data:

```
nsec + ""         →  npub_A  →  Storage bucket A (default)
nsec + "personal" →  npub_B  →  Storage bucket B
nsec + "work"     →  npub_C  →  Storage bucket C
```

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
      "hash": "<SHA-256 of canonical block payload for integrity verification>",
      "shares": [
        {"id": "<share0_sha256>", "server": "https://blossom1.example.com", "auth": "blob"},
        {"id": "<share1_sha256>", "server": "https://blossom2.example.com", "auth": "blob"},
        {"id": "<share2_sha256>", "server": "https://blossom3.example.com", "auth": "blob"}
      ]
    },
    {
      "index": 1,
      "hash": "<SHA-256 of canonical block payload>",
      "shares": [
        {"id": "<share0_sha256>", "server": "https://blossom1.example.com", "auth": "blob"},
        {"id": "<share1_sha256>", "server": "https://blossom2.example.com", "auth": "blob"},
        {"id": "<share2_sha256>", "server": "https://blossom3.example.com", "auth": "blob"}
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

The `hash` field in each block entry contains the SHA-256 hash of the canonical block payload before random padding is added. For file content blocks, the payload is `payload = [content_length: u32_be] || content`, where `content` has exactly `content_length` bytes. Random padding bytes are excluded from this hash because they are discarded during decoding and need not be reproduced during repair. This enables integrity verification after decryption: if the decrypted block's canonical payload hash doesn't match, either the ciphertext was corrupted, the wrong key was used, or the inode itself is corrupt.

The `shares` array is ordered by share index (0 to n-1). The array position determines the share index, which is required for erasure decoding. During reconstruction, the client fetches shares from their listed servers, tracking which indices were successfully retrieved. Once k shares are obtained, decoding can proceed. Storing share indices in the inode (rather than embedding them in share data) provides better privacy: servers cannot determine a share's position in the erasure scheme.

Each share descriptor contains:
- `id`: lowercase hex SHA-256 of the stored share bytes
- `server`: absolute HTTPS base URL used for authenticated `PUT` and `DELETE` requests
- `url`: optional absolute retrieval URL used for `GET` and `HEAD`; if omitted, clients derive it as `server + "/" + id`
- `auth`: authentication mode used for writes to that server: `"blob"` (per-blob key), `"identity"` (storage identity key), or `"none"` (server accepts unauthenticated writes)

The `auth` field is required for interoperable deletion and repair. The optional `url` field is required whenever the server returns a retrieval endpoint on a different origin than the write endpoint. Recovery clients MUST use `url` for reads when present, and MUST use `server` plus `auth` for uploads, repairs, and deletions.

The client stores inodes as blobs using the same pipeline: serialize, pad, encrypt, erasure-code, and distribute. The resulting structure's content hash forms a node in the Merkle DAG.

### 7.1 Large Inodes

Any inode (file or directory) may exceed the plaintext capacity C when serialized. With (n=5, k=3) erasure coding, each block entry requires approximately 500 bytes for share IDs and server URLs. A file with 500,000 blocks or a directory with thousands of entries could exceed the block size limit.

When an inode exceeds C bytes, it is stored as multiple blocks using the same framing and hashing rules as file content:

1. Serialize the inode to JSON
2. Split the serialized bytes into payload chunks of at most `C_eff` bytes, then frame each chunk as `[content_length || content || random_padding]` per Section 4.1
3. Encrypt each block with a key derived from a single `inode_id`
4. Erasure-code and upload each encrypted block
5. The parent reference includes the `inode_id` and block list

A multi-block inode reference in a directory entry:

```json
{
  "photos": {
    "type": "directory",
    "ref": {
      "format": "multi",
      "inode_id": "<base64-encoded 32-byte random identifier>",
      "erasure": {"algorithm": "reed-solomon", "k": 2, "n": 3, "field": "gf256"},
      "blocks": [
        {
          "index": 0,
          "hash": "<SHA-256 of canonical block payload>",
          "shares": [
            {"id": "<share0_sha256>", "server": "https://blossom1.example.com", "auth": "blob"},
            {"id": "<share1_sha256>", "server": "https://blossom2.example.com", "auth": "blob"},
            {"id": "<share2_sha256>", "server": "https://blossom3.example.com", "auth": "blob"}
          ]
        },
        {
          "index": 1,
          "hash": "<SHA-256 of canonical block payload>",
          "shares": [...]
        }
      ]
    }
  }
}
```

The `inode_id` inside a multi-block inode reference serves the same purpose as `file_id` for file content, enabling deterministic key derivation for multi-block data:

```
inode_key = HKDF-Expand(metadata_key, "garland-v1:inode:" || inode_id, 32)
block_key = HKDF-Expand(inode_key, "garland-v1:block:" || block_index_as_u64_be, 32)
```

Each block is then encrypted using the standard enc/mac key split: derive `enc_key` and `mac_key` from `block_key` via HKDF-Expand (Section 6.2), then encrypt with ChaCha20 and authenticate with HMAC-SHA256 using a random nonce. The `hash` field for each large-inode block follows the same canonical-payload rule as file blocks: `SHA256([content_length: u32_be] || content)`.

For single-block inodes (the common case), the inode is encrypted directly with `metadata_key` and the nonce is embedded in the encrypted block. The plaintext still uses the Section 4.1 framed block format with `C_eff` content capacity. Implementations should use this simpler approach when the serialized inode fits in one block.

This unified approach means the same chunking mechanism handles large files, large directories, and any future large metadata. Implementations use one code path for all cases.

### 7.2 Inline Small Files

Files below a configurable size threshold (default: 4 KiB) MAY be stored inline within their inode, avoiding the overhead of a separate block pipeline. A 100-byte file stored as a full block requires B bytes of encrypted storage plus n shares of size B/k each -- hundreds of kilobytes for a few bytes of content. Inlining eliminates this waste.

An inline inode stores the encrypted file content directly:

```json
{
  "version": 1,
  "type": "file",
  "size": 95,
  "created": 1701820800,
  "modified": 1701907200,
  "file_id": "<base64-encoded 32-byte random identifier>",
  "inline": "<base64-encoded encrypted content>",
  "erasure": {
    "algorithm": "reed-solomon",
    "k": 2,
    "n": 3,
    "field": "gf256"
  }
}
```

When the `inline` field is present, the `blocks` array is omitted. The inline content is encrypted with the file's `file_key` (derived from `master_key` and `file_id`, see Section 6.1), NOT with `metadata_key`. This preserves key separation: an attacker who compromises `metadata_key` can read the inode structure (filenames, sizes, timestamps, and the opaque `inline` ciphertext) but cannot decrypt the file content without `master_key`.

The inline ciphertext uses the same authenticated encryption format as block content:

```
enc_key = HKDF-Expand(file_key, "garland-v1:enc", 32)
mac_key = HKDF-Expand(file_key, "garland-v1:mac", 32)
nonce = random_bytes(12)
ciphertext = ChaCha20(enc_key, nonce, file_content)
mac = HMAC-SHA256(mac_key, nonce || ciphertext)
inline_value = base64(nonce || ciphertext || mac)
```

Note that the block index derivation step is skipped for inline content (there is no `block_key`; `enc_key` and `mac_key` are derived directly from `file_key`). No inner padding is needed: the file size is already visible in the `size` field to anyone who can decrypt the inode with `metadata_key`.

The resulting inode (containing the inline ciphertext) is then encrypted with `metadata_key` and stored through the normal inode pipeline. This produces double encryption (`file_key` inside `metadata_key`), which is a standard and safe cryptographic pattern.

Implementations SHOULD inline files when the serialized inode (including inline content) fits within a single block's plaintext capacity C. Implementations MUST support reading inline inodes even if they do not write them.

---

## 8. Directory Hierarchy

### 8.1 Directories as Encrypted Blobs

Garland uses a single canonical inode reference format everywhere a blob graph points to another inode: directory entries, commit roots, and any preserved historical commit references. Every inode reference MUST include enough information for an independent implementation to fetch and decode it without relying on bucket-global defaults.

Single-block inode reference:

```json
{
  "format": "single",
  "hash": "<content hash of encrypted inode blob>",
  "erasure": {
    "algorithm": "reed-solomon",
    "k": 2,
    "n": 3,
    "field": "gf256"
  },
  "shares": [
    {"id": "<share0_sha256>", "server": "https://blossom1.example.com", "auth": "blob"},
    {"id": "<share1_sha256>", "server": "https://blossom2.example.com", "auth": "blob"},
    {"id": "<share2_sha256>", "server": "https://blossom3.example.com", "auth": "blob"}
  ]
}
```

Multi-block inode reference:

```json
{
  "format": "multi",
  "inode_id": "<base64-encoded 32-byte random identifier>",
  "erasure": {
    "algorithm": "reed-solomon",
    "k": 2,
    "n": 3,
    "field": "gf256"
  },
  "blocks": [
    {
      "index": 0,
      "hash": "<SHA-256 of canonical block payload>",
      "shares": [
        {"id": "<share0_sha256>", "server": "https://blossom1.example.com", "auth": "blob"},
        {"id": "<share1_sha256>", "server": "https://blossom2.example.com", "auth": "blob"},
        {"id": "<share2_sha256>", "server": "https://blossom3.example.com", "auth": "blob"}
      ]
    }
  ]
}
```

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
      "ref": {
        "format": "single",
        "hash": "<content hash of photos directory inode blob>",
        "erasure": {"algorithm": "reed-solomon", "k": 2, "n": 3, "field": "gf256"},
        "shares": [
          {"id": "<share0_sha256>", "server": "https://blossom1.example.com", "auth": "blob"},
          {"id": "<share1_sha256>", "server": "https://blossom2.example.com", "auth": "blob"},
          {"id": "<share2_sha256>", "server": "https://blossom3.example.com", "auth": "blob"}
        ]
      }
    },
    "documents": {
      "type": "directory",
      "ref": {
        "format": "single",
        "hash": "<content hash of documents directory inode blob>",
        "erasure": {"algorithm": "reed-solomon", "k": 2, "n": 3, "field": "gf256"},
        "shares": [...]
      }
    },
    "notes.txt": {
      "type": "file",
      "ref": {
        "format": "single",
        "hash": "<content hash of notes.txt inode blob>",
        "erasure": {"algorithm": "reed-solomon", "k": 2, "n": 3, "field": "gf256"},
        "shares": [...]
      }
    }
  }
}
```

Each entry contains a `ref` object with the full inode reference. Single-block references carry the encrypted inode blob hash and share locations directly. Multi-block references carry an `inode_id`, erasure parameters, and per-block share lists. Readers MUST use the erasure parameters from the reference itself, not infer them from bucket defaults or current client configuration.

Implementations SHOULD use a single bucket-wide erasure profile for ordinary operation. The per-reference `erasure` field exists for decode safety and forward compatibility, not to encourage frequent per-blob parameter changes. Reusing one profile across a bucket keeps share sizes uniform and minimizes privacy leakage from server-visible blob dimensions.

The client encrypts and stores directory blobs identically to file inodes: same block size, same authenticated encryption, same erasure coding. Entry names remain within the encrypted blob, invisible to servers.

### 8.2 Merkle DAG Structure

The directory hierarchy forms a Merkle Directed Acyclic Graph (DAG), a tree-like structure where authenticated references point from parent nodes to child nodes. Any modification to a child changes either the encrypted blob hash (for single-block nodes) or the ordered block metadata inside its inode reference (for multi-block nodes), which propagates upward when parents are rewritten.

Single-block nodes are identified by the content hash of their encrypted representation. Multi-block nodes are identified by their full inode reference (`inode_id`, erasure parameters, and ordered block list).

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

This structure provides several important properties. Any authenticated inode reference validates the child subtree it names: if an attacker modifies any descendant, share hashes, block hashes, or inode-reference checks will fail during traversal. The structure can be verified incrementally; a client can validate a path from root to a specific file without fetching the entire tree. Unchanged subtrees share storage; updating one file doesn't require re-uploading siblings.

### 8.3 Path Resolution

To resolve a path like `/photos/image1.jpg`, the client:

1. Obtains the root inode reference from the current chain head
2. Fetches and decrypts the root directory inode from that reference
3. Looks up `"photos"` in the entries, obtaining the child inode reference
4. Fetches and decrypts the photos directory inode
5. Looks up `"image1.jpg"` in the entries, obtaining the file inode reference
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
    ["prev", "<event ID of previous commit>"]
  ],
  "content": "<encrypted payload>",
  "sig": "<Schnorr signature>"
}
```

The `prev` tag contains the event ID of the immediately preceding commit, creating the chain. The genesis commit omits this tag. The `created_at` timestamp provides temporal ordering; Nostr relays serve events in reverse chronological order by default, enabling efficient head discovery (see Section 9.5).

The client encrypts the `content` field using ChaCha20 with the commit key derived from the master storage key (see Section 6.1). It contains:

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

The complete history is recoverable by walking the chain backward from the head. Each commit's `prev` tag leads to its predecessor until reaching the genesis commit, which omits the `prev` tag entirely.

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
2. Build an index: `event_id → event` and `prev → event_id`
3. Identify the head: the event whose ID appears in no other event's `prev` tag
4. Walk backward via `prev` tags until reaching genesis (the commit with no `prev` tag)

This traversal reconstructs the complete history without requiring any decryption. The chain structure is visible in plaintext `prev` tags; only the content (root hashes, garbage lists, messages) requires decryption.

#### Fork Detection

Forks occur when two commits share the same `prev` value, meaning both claim to follow the same parent. During traversal:

1. If multiple events have the same `prev`, a fork exists
2. The event with the later `created_at` timestamp is the canonical head
3. The other branch may contain commits that need merging or represent conflicting changes

For personal single-device usage, forks are rare. Multi-device deployments should implement merge strategies (Section 9.2).

### 9.6 Metadata Privacy

Commit events are publicly visible on relays. To minimize metadata leakage, sensitive fields are encrypted within the `content` field:

- **Root hash**: Stored only in encrypted content. Observers cannot detect when the filesystem changes or correlate commits with blob uploads.
- **Garbage list**: Stored only in encrypted content. Observers cannot determine when data is being deleted.
- **Commit message**: Stored only in encrypted content.

The only plaintext metadata exposed is:
- The `prev` tag linking to the parent commit (necessary for chain traversal)
- The `created_at` timestamp (required by Nostr protocol)
- The owner's public key (inherent to Nostr signatures)

The `prev` tag reveals chain structure but not contents. Observers can count commits and analyze timing patterns from `created_at` timestamps, but cannot determine what changed between commits or how much data each commit affects. Users concerned about timing analysis can batch commits or add random delays to `created_at` values (within Nostr's tolerance for clock skew).

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

For full history recovery, omit the limit parameter in step 4, fetch all commits, and traverse the chain via `prev` tags as described in Section 9.5.

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

Some servers require authentication for write operations (PUT, DELETE) via a Nostr event in the Authorization header. Other servers operate openly without authentication. Share descriptors record this as `auth: "none"`.

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
  "content": "garland upload authorization",
  "sig": "<signature from per-blob key>"
}
```

The `t` tag specifies the authorized action: "upload" or "delete". The `x` tag binds the authorization to a specific blob hash. The `expiration` tag limits the authorization's validity window.

With per-blob keys, each blob appears to come from a different user. Servers cannot correlate blobs by pubkey, cannot determine total storage per user, and cannot link uploads across time.

#### Identity Key Mode

For servers requiring a billing relationship or account management, users may opt into identity key mode, where all authorizations use the storage identity pubkey directly. This enables per-user quotas and billing but allows the server to correlate all blobs to the same owner.

Identity key mode is selected per-server in client configuration and recorded as `auth: "identity"` in stored share descriptors. Open servers are recorded as `auth: "none"`. Users should prefer per-blob keys for privacy-focused servers and identity keys only where billing integration requires it.

#### Server Verification

Servers verify the signature, confirm the kind is 24242, check that the action matches the `t` tag, validate that the current time is before expiration, and verify the `x` tag matches the blob hash.

For authenticated servers, Garland defines an additional delete-ownership rule: the upload authorization also establishes delete authority. A Garland-compatible server MUST persist the authorization pubkey used for each accepted blob hash. A later `DELETE /{sha256}` MUST be accepted only if the authorization event is signed by the same pubkey that authorized the upload, or by an account-level key explicitly configured by the server for identity-key mode. A valid signature by some unrelated pubkey is not sufficient.

This rule is stricter than baseline Blossom interoperability. A generic Blossom server that does not implement Garland's delete-ownership rule is still usable as an append-only server for `PUT`, `GET`, and `HEAD`, but Garland clients MUST NOT assume that `DELETE` will work safely there. Clients SHOULD mark such servers as non-GC targets.

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

The `url` may differ from the upload endpoint if the server uses a CDN or different domain for retrieval.

Clients MUST persist both write and read semantics in share descriptors:
- `server`: the authenticated write/delete origin used for `PUT /upload` and `DELETE /{sha256}`
- `url`: the absolute retrieval URL returned by the server for `GET`/`HEAD`

If the returned `url` is exactly `server + "/" + sha256`, clients MAY omit `url` from stored metadata and derive it on demand. If it differs, clients MUST store it explicitly.

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
    {"id": "<share0_hash>", "server": "https://blossom1.example.com", "url": "https://cdn1.example.com/<share0_hash>", "auth": "blob"},
    {"id": "<share1_hash>", "server": "https://blossom2.example.com", "auth": "blob"},
    {"id": "<share2_hash>", "server": "https://blossom3.example.com", "auth": "blob"}
  ]
}
```

Clients fetch shares from `url` when present, otherwise from `server/{id}`. Uploads and deletes always target the `server` origin. There is no automatic discovery mechanism for finding alternative servers that may also host a given share.

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

Computing reachability requires traversing the Merkle DAG from each preserved commit's root. The traversal must handle each blob type appropriately:

**Directory blobs**: Extract `entries[i].hash` for each entry; these are content hashes of child inodes. Also collect the directory blob's own share IDs (from the parent's reference to it).

**File inodes**: Extract `blocks[i].shares[j].id` for all shares of all blocks; these are the share hashes stored on servers. Also collect the inode blob's own share IDs. Note that the `blocks[i].hash` field is a plaintext integrity hash, not a server-stored blob.

**Large file inodes**: Extract `block_index_chunks[i].shares[j].id` for all indirect block shares, then traverse each indirect block to collect the actual content share IDs within.

**Indirect block chunks**: Extract `blocks[i].shares[j].id` for all content shares referenced by this chunk.

```
reachable_shares = {}

def traverse_from_commit(commit):
    root_inode_shares = commit.root_inode.shares
    for share in root_inode_shares:
        reachable_shares.add(share.id)
    traverse_inode(fetch_and_decrypt(root_inode_shares))

def traverse_inode(inode):
    if inode.type == "directory":
        for entry in inode.entries:
            for share in entry.shares:
                reachable_shares.add(share.id)
            child = fetch_and_decrypt(entry.shares)
            traverse_inode(child)
    elif inode.type == "file":
        if inode.blocks:  # direct blocks
            for block in inode.blocks:
                for share in block.shares:
                    reachable_shares.add(share.id)
        if inode.block_index_chunks:  # large file indirect blocks
            for chunk in inode.block_index_chunks:
                for share in chunk.shares:
                    reachable_shares.add(share.id)
                indirect = fetch_and_decrypt(chunk.shares)
                for block in indirect.blocks:
                    for share in block.shares:
                        reachable_shares.add(share.id)
```

Shares not in `reachable_shares` are candidates for deletion. This includes old file content, old inodes, and old directory blobs from previous versions.

### 13.3 Deletion Strategies

Several strategies for garbage collection exist, offering different tradeoffs:

**Keep everything**: Never delete blobs. Storage grows unboundedly, but complete history is preserved. Suitable for archival use cases where history has intrinsic value.

**Keep recent history**: Preserve the last N commits or commits from the last M days. Delete blobs unreachable from this window. Balances storage cost against useful history depth.

**Keep only current**: Preserve only the chain head. Delete all blobs unreachable from the current state. Minimizes storage but loses all history. Recovery options are limited if the current state is corrupted.

**Explicit snapshots**: Mark specific commits as preserved (e.g., monthly snapshots, pre-migration backups). Delete blobs unreachable from any preserved commit.

### 13.4 Deletion Process

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

### 13.5 Metadata Event Garbage Collection

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
- The `prev` tag linking commits into a chain
- The encrypted `content` field (opaque ciphertext)
- The total number of commits over time
- Timing patterns of commit activity

**Not observable:**
- The root hash or any blob references (encrypted in content)
- Commit messages (encrypted in content)
- Garbage collection lists (encrypted in content)
- What changed between commits
- Dataset size or structure

The `prev` tag reveals that commits form a chain but not what the chain contains. An observer can count commits and analyze timing but cannot determine whether a commit added one file or a thousand, or whether it deleted data via garbage collection.

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
3. Generate a random per-file encryption key
4. For each block:
   - Derive the block encryption key
   - Encrypt with ChaCha20
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

The encryption is semantically secure: identical plaintexts produce different ciphertexts due to random per-file keys. Servers cannot detect when users store the same content.

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

Content addressing naturally deduplicates identical files since they hash to the same blob. Block-level deduplication across files is more complex. Content-defined chunking using rolling hashes (Rabin fingerprinting) could identify common blocks across similar files, reducing storage for versioned documents or near-duplicates.

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

12. IETF RFC 8785. JSON Canonicalization Scheme (JCS). https://www.rfc-editor.org/rfc/rfc8785

---

## Appendix A: Recommended Parameters

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Block size (B) | 262,144 bytes (256 KiB) | Fixed for all k values; balance between padding overhead and chunking granularity |
| Plaintext frame (C) | B - 44 = 262,100 bytes | Reserves space for 12-byte nonce + 32-byte MAC |
| Content capacity (C_eff) | C - 4 = 262,096 bytes | Reserves 4 bytes for length prefix in every block |
| Erasure coding | (n=5, k=3) | Tolerates 2 failures with 67% overhead |
| Encryption | ChaCha20 (RFC 8439) + HMAC-SHA256 | IETF variant, 96-bit nonce, NIP-44 aligned |
| Key derivation | HKDF-SHA256 | Standard, widely implemented |
| Commit relays | 5+ | Ensures retrievability despite relay failures |
| Verification | Weekly | Balances failure detection and bandwidth |
| Passphrase KDF | PBKDF2, 210k iterations | OWASP 2023 aligned, ~0.5-1s derivation |

---

## Appendix B: Reed-Solomon Test Vectors

All implementations MUST verify compatibility against these test vectors before deployment. These vectors were generated with `github.com/klauspost/reedsolomon` v1.12.4 using default settings (systematic encoding over GF(2^8)).

The common test input is the 12-byte block:

```
Input (hex): 000102030405060708090a0b
```

### (k=1, n=3)

```
Share 0: 000102030405060708090a0b
Share 1: 000102030405060708090a0b
Share 2: 000102030405060708090a0b
```

Reconstruction check: any 1 share reproduces the input block exactly.

### (k=2, n=3)

```
Share 0: 000102030405
Share 1: 060708090a0b
Share 2: 0c0d16171819
```

Reconstruction check: shares {0,2} and shares {1,2} both reconstruct `000102030405060708090a0b`.

### (k=3, n=5)

```
Share 0: 00010203
Share 1: 04050607
Share 2: 08090a0b
Share 3: 0c0d0e0f
Share 4: 10111213
```

Reconstruction check: shares {0,3,4} reconstruct `000102030405060708090a0b`.

### (k=4, n=6)

```
Share 0: 000102
Share 1: 030405
Share 2: 060708
Share 3: 090a0b
Share 4: fc9d56
Share 5: d7a849
```

Reconstruction check: shares {0,2,4,5} reconstruct `000102030405060708090a0b`.

### (k=4, n=7)

```
Share 0: 000102
Share 1: 030405
Share 2: 060708
Share 3: 090a0b
Share 4: fc9d56
Share 5: d7a849
Share 6: 9adb7c
```

Reconstruction check: shares {1,3,4,6} reconstruct `000102030405060708090a0b`.

### (k=6, n=9)

```
Share 0: 0001
Share 1: 0203
Share 2: 0405
Share 3: 0607
Share 4: 0809
Share 5: 0a0b
Share 6: 0c0d
Share 7: 0e0f
Share 8: 1011
```

Reconstruction check: shares {0,2,4,6,7,8} reconstruct `000102030405060708090a0b`.

Implementations SHOULD also publish machine-readable test vectors covering:
1. RS padding when `B mod k != 0`
2. Block framing and canonical payload hashes
3. Storage identity derivation and secp256k1 scalar rejection sampling
4. Commit encryption and inode-reference serialization
