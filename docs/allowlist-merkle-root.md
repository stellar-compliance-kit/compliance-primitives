# allowlist-token: Merkle-root allowlist mode

For large investor sets, writing every entry on-chain is expensive. In Merkle
mode the issuer publishes one 32-byte root with `set_allowlist_root(admin, root)`.
A holder proves membership by supplying the sibling hashes on the path from
their leaf to the root, using `is_allowed_with_proof(address, proof)` or
`transfer_with_proof(from, to, amount, from_proof, to_proof)`.

Merkle mode is separate from the on-chain entries used by `add_to_allowlist`,
`is_allowed` and `transfer`. The two can coexist, but only the proof functions
consult the root.

## Hash encoding

All hashes are SHA-256.

- **Leaf** for an address: `sha256(0x00 || S)`, where `S` is the address's
  StrKey string as ASCII bytes (`G...` for accounts, `C...` for contracts).
- **Internal node** for children `a` and `b` (each 32 bytes):
  let `lo` be the lexicographically smaller and `hi` the larger.
  `node = sha256(0x01 || lo || hi)`.
- **Proof**: the sibling hash at each level, from the leaf upward, as a
  `Vec<BytesN<32>>`. A proof may have at most `MAX_MERKLE_PROOF_LEN` (32) entries.
- **Verification**: start from the leaf hash, fold each sibling through the
  node function, and compare the result with the stored root.

The `0x00` and `0x01` prefixes separate leaves from internal nodes, so an
internal node cannot be passed off as a leaf. Sorting each pair means proofs
carry no left/right position bits.

An odd node at any level is promoted unchanged to the next level. It is not
hashed with a duplicate of itself.

## Generating a root (off-chain)

1. Collect the holder addresses and remove duplicates.
2. Compute each leaf hash.
3. Hash adjacent pairs level by level using the node rule. Promote an unpaired
   node unchanged.
4. Repeat until one hash remains. That is the root.
5. Publish it with `set_allowlist_root(admin, root)`.
6. For each holder, store the sibling list from their leaf to the root. Send it
   to them, or serve it from an API, so they can call `transfer_with_proof` or
   `is_allowed_with_proof`.

Use a standard Merkle library or write a small script that follows the encoding above.

## Limits

- Proof mode has no per-address expiration. Entries are valid until the root
  changes.
- Removing a holder means publishing a new root without them. Holders with
  old proofs stop passing as soon as the root changes.
- `set_allowlist_root` is blocked while the contract is paused, like the other
  allowlist writes.
