# Garland v0.1 Specification Review - Findings

**Review Date**: 2025-12-09

**Based on**: [garland-v0.1.md](https://github.com/andotherstuff/garland-protocol/blob/7f505fd970319fe3dc10daa7e61ab3036cda61e7/garland-v0.1.md) (commit 7f505fd)

**Author**: Johnathan Corgan, Corgan Labs

---

## Summary

This document presents prioritized findings from reviewing the Garland v0.1 specification.

**Overall Assessment**: The Garland specification presents a fundamentally sound architecture. The findings include:

- **Specification gaps**: Missing details needed for interoperable implementation (nonce strategies, Reed-Solomon parameters, share size handling)
- **Defense-in-depth recommendations**: Cryptographic improvements that provide safety margins against implementation bugs (AEAD, random padding, key hierarchy changes)
- **Specification corrections**: Claims that need revision (deduplication, server interchangeability)
- **Additional recommendations**: Protocol improvements (storage identifier separation, encrypted prev tag, incremental garbage collection)
- **Future directions**: Potential enhancements for efficiency (small file handling)

**Strengths of the Design**:

- **Layered architecture**: Clean separation of concerns
- **Per-blob authentication keys**: Excellent privacy feature (Section 11.2)
- **Content addressing**: Provides integrity without PKI complexity
- **Merkle DAG**: Efficient updates, structural integrity
- **Hash chain commits**: Auditability, history, conflict detection
- **Single-key recovery**: User sovereignty preserved
- **Erasure coding**: Practical durability mechanism
- **Threat model clarity**: Section 2.1 is explicit about assumptions

---

## 1. Specification Gaps (Missing Required Details)

### 1.1 Metadata Encryption Nonce Strategy [HIGH]

**Location**: Section 6.3

**Issue**: The spec states metadata is encrypted with `metadata_key` but does not specify the nonce strategy. Unlike file block encryption—which explicitly uses zero nonce with unique per-block derived keys—metadata encryption has no documented nonce approach. Without specification, implementations may diverge or inadvertently reuse nonces, causing keystream reuse.

**Recommendation**: Store a random 12-byte nonce in the parent reference for each metadata blob:

```json
{
  "inode": "<share_id>",
  "nonce": "<base64-encoded 12-byte random nonce>"
}
```

Encryption: generate random nonce, encrypt with `(metadata_key, nonce)`, store nonce in parent.
Decryption: read nonce from parent reference, decrypt.

**Broader note**: Random or pseudorandom nonces are security best practice for all uses of symmetric encryption. The 12-16 byte overhead per reference is minimal compared to other element sizes in this protocol (share IDs are 32 bytes, server URLs are 30-50+ bytes). The spec should adopt random nonces consistently across all encryption contexts—file blocks, metadata, and commit content. See also Finding 2.1 regarding authenticated encryption for file blocks.

---

### 1.2 Commit Content Encryption Nonce Strategy [HIGH]

**Location**: Section 9.1

**Issue**: The spec says commit `content` is encrypted with `commit_key` but no nonce is specified. There's one `commit_key` derived from master_key, used for all commits. Without a specified nonce strategy, implementations may diverge or inadvertently reuse nonces, causing keystream reuse across commits.

**Recommendation**: Use a random nonce, stored in a new `nonce` tag in the commit event:

```json
{
  "kind": 1097,
  "pubkey": "<storage pubkey>",
  "created_at": 1701907200,
  "tags": [
    ["prev", "<event ID of previous commit>"],
    ["nonce", "<base64-encoded 12-byte random nonce>"]
  ],
  "content": "<encrypted payload>",
  "sig": "<signature>"
}
```

The nonce tag is plaintext (like `prev`), which is fine—nonces don't need to be secret, only unique.

---

### 1.3 Share Size When B mod k ≠ 0 [MEDIUM]

**Location**: Section 5.2

**Issue**: The spec says "Divide the block into k pieces, each of size B/k bytes" but doesn't address non-divisibility. With B=256KiB and k=3: 262,144 / 3 = 87,381.33 bytes.

**Impact**: Implementation ambiguity; potential privacy leak if shares have different sizes.

**Recommendation**: Add constraint:

> "The block size B MUST be chosen such that B is evenly divisible by k. Alternatively, implementations MUST pad the block to the next multiple of k bytes before splitting."

Practical guidance—recommended (B, k) pairs:

| k | B | B/k |
|---|---|-----|
| 2 | 256 KiB (262,144) | 131,072 |
| 3 | 255 KiB (261,120) | 87,040 |
| 4 | 256 KiB (262,144) | 65,536 |
| 5 | 255 KiB (261,120) | 52,224 |

---

### 1.4 Reed-Solomon Construction Parameters [MEDIUM]

**Location**: Section 5.2

**Issue**: The spec describes Reed-Solomon encoding conceptually but doesn't pin down the exact construction:

> "In practice, encoding multiplies the source vector by a k × n generator matrix (typically derived from a Vandermonde or Cauchy matrix)."

"Typically" and "or" leave room for incompatible implementations.

**Impact**: Two implementations using different generator matrices will produce different shares from the same input, breaking interoperability entirely.

**Recommendation**: The spec must define canonical parameters. Add to Section 5.2:

> **Canonical Reed-Solomon Construction**
>
> For interoperability, all implementations MUST use identical Reed-Solomon parameters. The specification defines:
>
> - Field representation
> - Generator matrix construction
> - Whether encoding is systematic
>
> For example, a suitable choice would be:
>
> - Field: GF(2^8) with irreducible polynomial 0x11D
> - Generator matrix: Vandermonde with evaluation points [1, 2, ..., n]
> - Encoding: Systematic
>
> The exact parameters should be chosen based on library availability and performance characteristics, but once chosen, MUST be documented precisely and used by all conforming implementations.

---

### 1.5 Unified Inode Model for Large Data [HIGH]

**Location**: Sections 7.1 and 8

**Issue**: The spec treats files, directories, and large file inodes as distinct concepts requiring different handling:

- Files exceeding ~500 blocks use a special "indirect" structure with block index chunks
- Directories are stored "identically to file inodes" but large directory handling is unaddressed
- Block index chunks need their own encryption key specification (currently unspecified)

**Key insight**: At the storage layer, everything is just an encrypted blob:

- A **file** is an inode pointing to block data
- A **directory** is an inode pointing to other inodes by name
- An **inode** is an encrypted blob

There's no fundamental reason to treat any of these differently when they exceed block size—they're all just data that needs chunking.

**Recommendation**: Unify the model. Define an inode as content-addressed encrypted data that may reference other inodes. When any inode (file, directory, or otherwise) exceeds block size:

- Split into blocks, encrypt, erasure-code each block
- Parent references the inode with a block list, same as inodes reference file content

**Benefits**:

- One mechanism for large data (files, directories, inodes—all the same)
- No special "indirect block index" structure
- Simpler implementation—same code path handles all cases
- No need to specify indirect block chunk encryption (eliminated by design)
- Large directories handled automatically

---

## 2. Design Recommendations (Defense-in-Depth)

### 2.1 Consider Authenticated Encryption for Blocks [HIGH - Recommendation]

**Location**: Section 6.2

**Current design**: ChaCha20 with zero nonce, relying on fresh `file_key` per file version.

**The concern**: This relies on implementation correctness with no cryptographic enforcement. A buggy client that reuses a file_key (e.g., during a file update) would cause catastrophic failure—and neither the client nor anyone else could detect it after the fact.

**Two separate improvements**:

1. **Random nonces**: Even with plain ChaCha20, using random nonces (stored in the inode) provides defense-in-depth against key reuse bugs. This aligns with NIP-44's approach, which uses ChaCha20 with random nonces and derives per-message keys via HKDF.

2. **Authentication**: Adding authentication (via Poly1305 or HMAC) detects tampering before decryption. Currently, integrity relies solely on content addressing—the block hash in the inode verifies correctness after decryption. Authentication catches corruption earlier.

**Trade-offs**:

| Approach | Overhead per block | Safety |
|----------|-------------------|--------|
| Current (zero nonce) | 0 bytes | Relies on correct implementation |
| Random nonce only | 12 bytes | Defense against key reuse |
| ChaCha20-Poly1305 + random nonce | 28 bytes (12 nonce + 16 tag) | Key reuse protection + authentication |

For 256 KiB blocks, 28 bytes is 0.01% overhead.

**Recommendation**: At minimum, adopt random nonces for consistency with Findings 1.1 and 1.2. Consider adding authentication (Poly1305 or HMAC) for defense-in-depth, though content addressing already provides post-decryption integrity verification.

---

### 2.2 Consider Random Padding [MEDIUM - Recommendation]

**Location**: Section 4.1

**Current design**: Zero-fill padding for the final block:

```text
Final block: [content_length: u32_be][content: content_length bytes][padding: zeros]
```

**The concern**: Zero-fill padding provides known plaintext at predictable locations, violating the principle of avoiding predictable plaintext in ciphertext.

**Recommendation**: Use random padding:

```text
Final block: [content_length: u32_be][content: content_length bytes][padding: random bytes]
```

The padding bytes are discarded on decode (the `content_length` field tells the decoder where content ends), so they don't need to be reproducible.

---

### 2.3 Derive File Keys from Master Key [HIGH - Recommendation]

**Location**: Sections 6.1 and 7

**Current design**: Per-file keys are random, encrypted with `metadata_key`, and stored in inodes:

> "The `key` field contains the per-file encryption key, encrypted with the metadata key."

**The problem**: The key hierarchy provides no real separation between metadata and content. An attacker who obtains `metadata_key` can:

1. Decrypt inodes (intended—metadata access)
2. Extract encrypted file keys from inodes
3. Decrypt file keys with the same `metadata_key`
4. Decrypt all file content

The current design encrypts file keys with `metadata_key`, which means `metadata_key` is effectively the content key. The apparent separation between "structural metadata" and "file content" is illusory—compromising one compromises both.

**Recommendation**: Derive file keys from `master_key` using a random file identifier:

```text
file_id = random_bytes(32)  # stored plaintext in inode
file_key = HKDF-Expand(master_key, "garland-v1:file:" || file_id, 32)
```

Inode structure becomes:

```json
{
  "version": 1,
  "type": "file",
  "file_id": "<base64-encoded 32-byte random identifier>",
  ...
}
```

**Why this matters**:

- `metadata_key` compromise now reveals only structure (filenames, timestamps, sizes)—not content
- Content access requires `master_key`, which is never derived from `metadata_key`
- No encrypted key material stored—file keys are derived on demand from `master_key` + `file_id`
- `file_id` in plaintext is meaningless without `master_key`
- File modification generates new `file_id`, ensuring fresh keys per version

This restores the intended separation: metadata access and content access are cryptographically independent.

---

## 3. Specification Corrections

### 3.1 Deduplication Claim [MEDIUM - Correction]

**Location**: Section 17.4

**Current text**:
> "Content addressing naturally deduplicates identical files since they hash to the same blob."

**Issue**: This is inaccurate for Garland's encryption design. Per Section 6.1:
> "Each file receives a randomly generated 256-bit key at creation time."

With random per-file keys:

- Same plaintext + different keys → different ciphertext → different hash
- No deduplication occurs

This applies both across users and within a single user storing the same file twice.

**Recommendation**: Rewrite Section 17.4:

> **17.4 Deduplication**
>
> The current design prioritizes semantic security over deduplication. Random per-file keys ensure identical plaintexts produce different ciphertexts, preventing servers from detecting duplicate content. Deduplication is not supported.

---

### 3.2 Server Interchangeability Clarification [LOW - Correction]

**Location**: Section 11.4

**Current text**:
> "Blossom servers are interchangeable and fungible. A blob uploaded to server A can be retrieved from server B if server B also has it."

**Issue**: While technically true, this is misleading in context. Inodes bind specific server URLs for each share:

```json
{
  "shares": [
    {"id": "<share0_hash>", "server": "https://blossom1.example.com"},
    {"id": "<share1_hash>", "server": "https://blossom2.example.com"}
  ]
}
```

There's no discovery mechanism. A client can't find out that `blossom3.example.com` also has the share—it only knows about servers listed in the inode.

**Recommendation**: Clarify Section 11.4:

> **Server Selection and Inode Binding**
>
> Blossom servers are interchangeable in that any server can store and serve any blob by its content hash. However, inodes explicitly list the server URLs where each share was uploaded. Clients fetch from these listed servers.
>
> "Interchangeability" means:
>
> 1. Clients can choose which k of n listed servers to fetch from
> 2. During repair, failed servers can be replaced by uploading shares to new servers and updating the inode
>
> The design does not include automatic discovery of alternative servers hosting a given share.

---

## 4. Additional Recommendations

### 4.1 k=1 Replication Hash Correlation [LOW - Recommendation]

**Location**: Section 5.4

**Issue**: With k=1 (simple replication), all servers store identical copies of the encrypted block, so all shares have the same hash. This enables trivial cross-server correlation. The spec acknowledges this:

> "Note that with k=1, all servers store blobs with identical hashes, enabling potential cross-server correlation; with k>1, each share has a unique hash."

**Recommendation**: Mitigate by prepending a header containing the share index:

```text
share_i = [share_index: u8] || encrypted_block
```

Each share would then have different content and thus a different hash, even with k=1. The header is stripped after retrieval.

This small overhead (1 byte per share) eliminates cross-server hash correlation for all values of k.

---

### 4.2 Incremental Garbage Collection Algorithm [LOW - Recommendation]

**Location**: Section 13

**Current design**: The spec includes a `garbage` array in each commit (Section 9.1) listing blobs no longer referenced. However, Section 13.2 describes garbage collection as requiring full Merkle DAG traversal to compute reachability.

**Observation**: The `garbage` array already provides the information needed for incremental collection without DAG traversal. Each commit's `garbage` list contains exactly the blobs that became unreachable at that commit.

**Recommendation**: Add an incremental GC algorithm to Section 13:

> **Incremental garbage collection**: Walk the commit chain forward from the oldest commit you wish to discard. At each commit, delete the blobs in its `garbage` list from storage servers. Continue until reaching the oldest commit you wish to retain. This approach requires no DAG traversal and no client-side reachability computation—each commit already records what it obsoletes.

This leverages existing spec infrastructure for a simpler GC implementation.

---

### 4.3 Separate Storage Identifier from Passphrase [MEDIUM - Recommendation]

**Location**: Section 6.4

**Current design**: `nsec + passphrase` derives the storage identity.

**The concern**: The term "passphrase" implies high-entropy secret text, but in the current design it also serves to name different storage buckets. Using "work" or "personal" as a passphrase is weak from a security standpoint, yet that's the natural usage for naming buckets.

PBKDF2 difficulty only slows down attacks—it doesn't compensate for low-entropy input. An attacker brute-forcing common bucket names ("work", "personal", "backup", "photos") at 210k iterations each is still feasible. The protection comes from users choosing high-entropy passphrases, not from PBKDF2 alone.

**Recommendation**: Separate identifier from passphrase:

```text
storage_nsec = derive(nsec, identifier, passphrase)
```

Where:

- **Identifier**: Names the bucket (low entropy is fine—"work", "photos", "default")
- **Passphrase**: Protects the bucket (high entropy expected, can be empty)

**Benefits**:

- Terminology matches expectations—passphrase means secret, identifier means name
- Users won't mistakenly think "work" provides meaningful protection
- A bucket can have a clear name ("photos") with a strong passphrase
- Empty passphrase explicitly indicates unprotected bucket

---

### 4.4 Consider Encrypting Prev Tag [LOW - Recommendation]

**Location**: Section 9.1

**Current design**: The `prev` tag in commit events is plaintext:

```json
{
  "kind": 1097,
  "tags": [
    ["prev", "<event ID of previous commit>"]
  ],
  "content": "<encrypted payload>"
}
```

**What this leaks**:

- Complete commit chain structure visible to any observer
- Timing between commits (via `created_at` timestamps)
- Fork events publicly detectable
- Activity patterns observable

**The spec's justification**: Section 9.6 states this is necessary for chain traversal.

**Analysis**: This justification is weak. Recovery and traversal with encrypted `prev`:

1. Query relay for all kind 1097 events by storage pubkey
2. Decrypt each commit's content to find its `prev` value
3. Build the chain graph locally
4. Identify head (commit whose ID appears in no other's `prev`)

The commits must be decrypted anyway to access their content. The only additional cost is decrypting before knowing chain order rather than after.

**Recommendation**: Move `prev` into the encrypted commit content:

```json
{
  "kind": 1097,
  "tags": [],
  "content": "<encrypted: {prev, root_inode, garbage, message}>"
}
```

**Trade-off**: Relays can no longer index chain structure. Clients must fetch all commits by pubkey and build the graph locally after decryption. Since commits are small (a few hundred bytes each) and decryption is fast, this is practical even for extensive history. Relays can still filter by `created_at` for time-bounded queries.

---

### 4.5 Repair Optimization Note [LOW - Note]

**Location**: Section 12.3

**Current description**: The spec describes repair as decode-then-reencode:

> 1. Fetch surviving shares
> 2. Reconstruct the block (decode k shares to original)
> 3. Regenerate missing share (re-encode to produce all n, extract needed ones)

**Note**: This description is functionally correct and matches typical Reed-Solomon library APIs. However, the underlying math allows computing missing shares directly from any k surviving shares without full block reconstruction. Implementations using libraries that expose this capability can avoid the decode/re-encode overhead.

This is an optimization opportunity, not a specification error. The current description produces correct results.

---

## 5. Observations (Future Directions)

### 5.1 Small File Efficiency

**Location**: Section 4.2

The fixed 256 KiB block size is inefficient for small files (99.6% overhead for a 1 KB file). The spec acknowledges this and suggests application-level aggregation (tar, zip).

**Possible protocol-level alternatives for future consideration**:

1. **Pack files**: Blob-sized files containing multiple small file extents concatenated. Inodes for small files would reference these pack blobs with offset and length fields:

   ```json
   {
     "type": "file",
     "pack_ref": {
       "blob": "<pack blob share references>",
       "offset": 1024,
       "length": 512
     }
   }
   ```

2. **Inline content**: Encode small file content directly within the inode itself, avoiding a separate content blob entirely:

   ```json
   {
     "type": "file",
     "inline": true,
     "content": "<base64-encoded small file content>"
   }
   ```

These approaches are not mutually exclusive. Neither is required for a functional system—the current design works correctly, just with overhead for small files.
