// Copyright (c) 2026 Stellar Compliance Kit contributors
// SPDX-License-Identifier: MIT
// See the LICENSE file in the repository root for the full license text.

//! `allowlist-token` is a `#![no_std]` Soroban contract that wraps an existing
//! SEP-41 token and only permits `transfer` calls between two addresses that
//! are both present on an on-chain allowlist.
//!
//! **Purpose**: give issuers of permissioned tokens (e.g. RWA or regulated
//! stablecoins) a drop-in gate that blocks transfers to or from addresses
//! that haven't cleared KYC/onboarding, without modifying the underlying
//! token contract's own logic.
//!
//! **Composition**: deploy this contract in front of an issuer's real token
//! and point clients at it instead of the underlying token — cleared
//! transfers are forwarded on via a cross-contract call.
//!
//! **Roles**: `admin` is the primary privileged role. `add_to_allowlist`
//! (and `add_to_allowlist_delegated`) are admin-only. An optional
//! compliance officer, assigned with `set_compliance_officer` and removed
//! with `revoke_compliance_officer` (both admin-only), may call
//! `remove_from_allowlist` but can never grant access or manage roles.
//! Either role may also `freeze` / `unfreeze` an address: a frozen address
//! can neither send nor receive, but keeps its allowlist entry, so a holder
//! can be suspended during an investigation without losing their status.
//! The admin may `clawback` underlying tokens from an address (forwarded to
//! the underlying SEP-41 token's `clawback`), optionally only once that
//! address has been frozen (`set_clawback_requires_freeze`).
//!
//! **Delegated actions**: `add_to_allowlist_delegated` lets a relayer submit
//! an allowlist addition on the admin's behalf, without the admin account
//! signing the transaction. The admin first registers an ed25519 public key
//! with `set_delegated_admin_key`. The holder of the matching private key then
//! signs the payload
//! `allowlist-delegated-v2:<target>:add_to_allowlist:<nonce>:<expiry>:<valid_until_ledger>`,
//! where `<target>` is the address being allowlisted (strkey), `<nonce>` is a
//! `u64`, `<expiry>` is a ledger timestamp in seconds and
//! `<valid_until_ledger>` is the last ledger sequence (inclusive, `u32`) at
//! which the signature may be submitted. All numbers are base-10 ASCII. Each
//! admin has a replay-protection nonce: a call is rejected with
//! `InvalidNonce` unless `nonce` is strictly greater than the last accepted
//! one (readable via `get_delegated_nonce`), and with `ExpiredSignature` once
//! the ledger timestamp reaches `expiry` or the ledger sequence passes
//! `valid_until_ledger`. The ledger bound means a leaked but unsubmitted
//! signature stops being usable after a short window, so signers should pick
//! a `valid_until_ledger` only a few hundred ledgers ahead (e.g. ~720 ledgers
//! ≈ 1 hour at ~5s/ledger). Use this path when the admin key is kept
//! offline or in cold storage and a relayer pays the fees; use the direct
//! path (`admin.require_auth()`) whenever the admin can sign the transaction
//! itself.
//! `allowlist-token` is a Soroban contract that wraps an existing
//! SEP-41 token and only permits `transfer` calls between two addresses that
//! are both present on an on-chain allowlist.
//!
//! **Purpose**: give issuers of permissioned tokens (e.g. RWA or regulated
//! stablecoins) a drop-in gate that blocks transfers to or from addresses
//! that haven't cleared KYC/onboarding, without modifying the underlying
//! token contract's own logic.
//!
//! **Composition**: deploy this contract in front of an issuer's real token
//! and point clients at it instead of the underlying token — cleared
//! transfers are forwarded on via a cross-contract call.
//!
//! **Roles**: there is a single privileged role, `admin`. Both
//! `add_to_allowlist` and `remove_from_allowlist` are admin-only, and this
//! contract has no compliance-officer role (that role exists only on
//! `denylist-gate` and `jurisdiction-flag`). If an "officers may revoke but not
//! grant" split is ever wanted here, it must be added deliberately, with
//! `add_to_allowlist` staying admin-only.
#![no_std]

extern crate alloc;

use soroban_sdk::{
    contract, contracterror, contractevent, contractimpl, contractmeta, contracttype, token,
    Address, Bytes, BytesN, Env, String, Symbol, Vec,
};

contractmeta!(key = "version", val = env!("CARGO_PKG_VERSION"));
contractmeta!(key = "source", val = env!("CARGO_PKG_REPOSITORY"));

/// Extend a persistent allowlist entry when its remaining TTL drops below
/// this many ledgers (~7 days at ~5s/ledger on mainnet).
pub(crate) const ALLOWED_TTL_THRESHOLD: u32 = compliance_ttl::TTL_THRESHOLD; // ~7 days

/// Target remaining TTL after extension (~90 days at ~5s/ledger).
pub(crate) const ALLOWED_TTL_EXTEND_TO: u32 = compliance_ttl::TTL_EXTEND_TO; // ~90 days

/// Maximum number of addresses accepted by a batch allowlist operation.
pub const MAX_BATCH_SIZE: u32 = 45;

/// Maximum number of sibling hashes accepted in a Merkle allowlist proof.
/// 32 levels covers 2^32 holders and bounds the hashing cost of one check.
pub const MAX_MERKLE_PROOF_LEN: u32 = 32;

/// Instance-storage TTL policy: whenever the remaining instance TTL drops
/// below [`INSTANCE_TTL_THRESHOLD`], it is bumped back up to
/// [`INSTANCE_TTL_EXTEND_TO`]. Matches `compliance-aggregator`.
pub const INSTANCE_TTL_THRESHOLD: u32 = compliance_ttl::TTL_THRESHOLD; // ~7 days
/// Target instance TTL after an extension.
pub const INSTANCE_TTL_EXTEND_TO: u32 = compliance_ttl::TTL_EXTEND_TO; // ~90 days

#[contracttype]
#[derive(Clone)]
enum DataKey {
    /// The admin address, set once in `initialize`. Instance storage.
    Admin,
    /// Optional compliance officer, who may revoke allowlist entries. Instance storage.
    ComplianceOfficer,
    Token,
    Allowed(Address),
    Paused,
    PendingAdmin,
    /// ed25519 public key allowed to authorize delegated admin actions.
    DelegatedAdminPubKey,
    /// Last accepted delegated-action nonce for an admin. Persistent storage.
    DelegatedNonce(Address),
    PendingUpgrade,
    /// Marks an address as frozen. Independent of `Allowed`, so freezing and
    /// unfreezing never touches allowlist status or history. Persistent storage.
    Frozen(Address),
    /// When `true`, `clawback` only succeeds against a frozen address. Instance storage.
    ClawbackRequiresFreeze,
    /// Number of addresses currently holding an allowlist entry. Instance storage.
    AllowlistCount,
    /// Merkle root of the proof-based allowlist. Instance storage.
    AllowlistRoot,
    /// Global maximum balance any single address may hold. Instance storage.
    GlobalMaxBalance,
    /// Per-address maximum balance. Persistent storage.
    MaxBalance(Address),
    /// Number of addresses currently holding a non-zero balance. Instance storage.
    HolderCount,
    /// Optional cap on `HolderCount`. Absent = unlimited. Instance storage.
    MaxHolders,
    /// Who approved an allowlist entry and at which ledger. Kept under its own
    /// key, not inside `AllowlistEntry`, so existing entries keep their stored
    /// shape. Persistent storage.
    AllowedProvenance(Address),
}

#[contracttype]
#[derive(Clone)]
pub struct AllowlistEntry {
    pub expiration_ledger: Option<u32>,
}

/// Approval record for an allowlist entry: the admin that approved it and the
/// ledger it was approved at. Stored under `DataKey::AllowedProvenance`.
#[contracttype]
#[derive(Clone)]
pub struct AllowlistProvenance {
    pub added_by: Address,
    pub added_at_ledger: u32,
}

/// Allowlist entry as returned by `get_allowlist_entry`: the stored expiry
/// plus approval provenance. `added_by` and `added_at_ledger` are `None` for
/// entries approved before provenance was recorded.
#[contracttype]
#[derive(Clone)]
pub struct AllowlistEntryInfo {
    pub expiration_ledger: Option<u32>,
    pub added_by: Option<Address>,
    pub added_at_ledger: Option<u32>,
}

#[contractevent]
pub struct AllowAdd {
    #[topic]
    pub address: Address,
    /// Admin or compliance officer that authorized the change.
    pub by: Address,
}

#[contractevent]
pub struct AllowRemove {
    #[topic]
    pub address: Address,
    /// Admin or compliance officer that authorized the change.
    pub by: Address,
}

/// Emitted when an admin or compliance officer freezes `address`.
#[contractevent]
pub struct AddressFrozen {
    #[topic]
    pub caller: Address,
    #[topic]
    pub address: Address,
}

/// Emitted when an admin or compliance officer unfreezes `address`.
#[contractevent]
pub struct AddressUnfrozen {
    #[topic]
    pub caller: Address,
    #[topic]
    pub address: Address,
}

/// Emitted when the admin claws back `amount` of the underlying token from `from`.
#[contractevent]
pub struct Clawback {
    #[topic]
    pub admin: Address,
    #[topic]
    pub from: Address,
    pub amount: i128,
}

#[contractevent]
pub struct Blocked {
    #[topic]
    pub from: Address,
    #[topic]
    pub to: Address,
    pub amount: i128,
}

#[contractevent]
pub struct AdminTransferred {
    #[topic]
    pub old_admin: Address,
    #[topic]
    pub new_admin: Address,
}

#[contractevent]
pub struct AdminProposed {
    #[topic]
    pub current: Address,
    #[topic]
    pub proposed: Address,
}

#[contractevent]
pub struct UpgradeProposed {
    #[topic]
    pub admin: Address,
    pub new_wasm: BytesN<32>,
    pub activated_at: u64,
}

#[contractevent]
pub struct UpgradeCancelled {
    #[topic]
    pub admin: Address,
}

#[contractevent]
pub struct UpgradeCommitted {
    #[topic]
    pub admin: Address,
    pub new_wasm: BytesN<32>,
}

/// Emitted when `set_compliance_officer` assigns the compliance-officer role.
/// `previous` is the officer being replaced, if one was assigned.
#[contractevent]
pub struct ComplianceOfficerSet {
    #[topic]
    pub admin: Address,
    #[topic]
    pub officer: Address,
    pub previous: Option<Address>,
}

/// Emitted when `revoke_compliance_officer` clears the compliance-officer role.
/// `previous` is the officer that was revoked, if one was assigned.
#[contractevent]
pub struct ComplianceOfficerRevoked {
    #[topic]
    pub admin: Address,
    pub previous: Option<Address>,
}

/// Emitted when `set_delegated_admin_key` registers or rotates the ed25519
/// key that may authorize delegated admin actions.
#[contractevent]
pub struct DelegatedAdminKeySet {
    #[topic]
    pub admin: Address,
    pub previous: Option<BytesN<32>>,
    pub pubkey: BytesN<32>,
}

/// Emitted when a max-balance limit changes. `address` is `None` for the
/// global limit and `Some(holder)` for a per-address limit. `limit` is `None`
/// when the limit is removed.
#[contractevent]
pub struct MaxBalanceSet {
    #[topic]
    pub admin: Address,
    pub address: Option<Address>,
    pub limit: Option<i128>,
}

/// Emitted when `set_allowlist_root` publishes a new proof-mode allowlist root.
#[contractevent]
pub struct AllowlistRootSet {
    #[topic]
    pub admin: Address,
    pub root: BytesN<32>,
}

#[contractevent]
pub struct Paused {
    #[topic]
    pub admin: Address,
}

#[contractevent]
pub struct Unpaused {
    #[topic]
    pub admin: Address,
}

#[contracttype]
#[derive(Clone)]
pub struct Metadata {
    pub version: String,
    pub admin: Address,
}

/// Delayed upgrade proposal state.
#[contracttype]
#[derive(Clone)]
pub struct UpgradeState {
    pub new_wasm: BytesN<32>,
    pub activated_at: u64,
}

/// Current on-chain schema version for this contract instance.
pub const SCHEMA_VERSION: u32 = 1;

/// Version of the shared `ComplianceCheck` interface implemented by
/// [`AllowlistToken::is_compliant`]. Bumped whenever the interface's
/// signature or semantics change; callers must compare this against the
/// version they were built against before calling `is_compliant`.
pub const COMPLIANCE_CHECK_INTERFACE_VERSION: u32 = 2;

/// Reason code returned by [`AllowlistToken::is_compliant`] when the address
/// is on the allowlist.
pub const CHECK_CODE_ALLOWED: u32 = 0;
/// Reason code returned by [`AllowlistToken::is_compliant`] when the address
/// has no allowlist entry.
pub const CHECK_CODE_NOT_ALLOWLISTED: u32 = 1;
/// Reason code returned by [`AllowlistToken::is_compliant`] when the address
/// has an allowlist entry whose `expiration_ledger` has passed.
pub const CHECK_CODE_ALLOWLIST_ENTRY_EXPIRED: u32 = 2;

/// Result of the shared `ComplianceCheck` interface.
///
/// `allowed` is the pass/fail verdict; `code` explains it. A `code` of
/// [`CHECK_CODE_ALLOWED`] (0) always accompanies `allowed == true`; any
/// non-zero `code` accompanies `allowed == false`.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckResult {
    pub allowed: bool,
    pub code: u32,
}

/// Minimum upgrade review window, approximately one day at five seconds per ledger.
pub const MIN_UPGRADE_DELAY_LEDGERS: u32 = 17_280;

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    NotInitialized = 1,
    AlreadyInitialized = 2,
    NotAuthorized = 3,
    /// Caller supplied an argument that is structurally invalid — e.g. a
    /// negative token amount.
    InvalidInput = 4,
    ContractPaused = 5,
    NoPendingAdmin = 6,
    PendingAdminMismatch = 7,
    DelegationNotConfigured = 8,
    InvalidSignature = 9,
    InvalidNonce = 10,
    ExpiredSignature = 11,
    /// `commit_upgrade` called with no pending upgrade, or before `activated_at`.
    UpgradeNotReady = 12,
    BatchTooLarge = 13,
    /// `transfer` involves an address that is currently frozen.
    AddressFrozen = 14,
    /// `clawback` was called against an address that is not frozen while
    /// `clawback_requires_freeze` is enabled.
    ClawbackRequiresFreeze = 15,
    /// A transfer would leave the recipient above the global or per-address
    /// maximum balance.
    MaxBalanceExceeded = 16,
    /// A transfer would add a new holder beyond the configured `MaxHolders`.
    MaxHoldersReached = 17,
}

#[contract]
pub struct AllowlistToken;

#[contractimpl]
impl AllowlistToken {
    /// One-time setup. `admin` may manage the allowlist; `token` is the
    /// address of the underlying SEP-41 token contract that real transfers
    /// are forwarded to once both parties clear the allowlist check.
    pub fn initialize(env: Env, admin: Address, token: Address) -> Result<(), Error> {
        Self::extend_instance_ttl(&env);
        if env.storage().instance().has(&DataKey::Admin) {
            return Err(Error::AlreadyInitialized);
        }
        admin.require_auth();
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::Token, &token);
        Ok(())
    }

    /// Returns metadata about this contract instance.
    pub fn metadata(env: Env) -> Result<Metadata, Error> {
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(Error::NotInitialized)?;
        Ok(Metadata {
            version: String::from_str(&env, env!("CARGO_PKG_VERSION")),
            admin,
        })
    }

    /// Return the configured admin address.
    pub fn get_admin(env: Env) -> Result<Address, Error> {
        env.storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(Error::NotInitialized)
    }

    /// Configure the ed25519 public key that may authorize delegated admin
    /// actions without the admin account itself needing to submit the
    /// transaction. The direct-auth path remains unchanged and still uses
    /// `admin.require_auth()`. Admin-only.
    ///
    /// Emits `DelegatedAdminKeySet { admin, previous, pubkey }`.
    pub fn set_delegated_admin_key(
        env: Env,
        admin: Address,
        pubkey: BytesN<32>,
    ) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        let previous: Option<BytesN<32>> = env
            .storage()
            .instance()
            .get(&DataKey::DelegatedAdminPubKey);
        env.storage()
            .instance()
            .set(&DataKey::DelegatedAdminPubKey, &pubkey);
        DelegatedAdminKeySet {
            admin,
            previous,
            pubkey,
        }
        .publish(&env);
        Ok(())
    }

    /// Returns the ed25519 public key currently registered with
    /// `set_delegated_admin_key`, or `None` if delegation is not configured.
    pub fn get_delegated_admin_key(env: Env) -> Option<BytesN<32>> {
        env.storage()
            .instance()
            .get(&DataKey::DelegatedAdminPubKey)
    }

    /// Add `address` to the allowlist. Admin-only.
    ///
    /// Granting access is deliberately stricter than revoking it: putting an
    /// address on the allowlist lets it receive and send the wrapped token, so
    /// it is restricted to the `admin` (directly, or through
    /// `add_to_allowlist_delegated`). The compliance officer may revoke access
    /// via `remove_from_allowlist` but never grant it.
    ///
    /// # Example
    ///
    /// ```ignore
    /// // `token` is an `AllowlistTokenClient` for the deployed contract.
    /// // Grant `alice` access until ledger `expiry`; `None` means no expiry.
    /// token.add_to_allowlist(&admin, &alice, &Some(expiry));
    /// token.add_to_allowlist(&admin, &bob, &None);
    /// ```
    pub fn add_to_allowlist(
        env: Env,
        admin: Address,
        address: Address,
        expiration_ledger: Option<u32>,
    ) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        if let Some(exp) = expiration_ledger {
            if exp < env.ledger().sequence() {
                return Err(Error::InvalidInput);
            }
        }
        Self::write_allowlist_entry(&env, &address, expiration_ledger, &admin);
        AllowAdd { address, by: admin }.publish(&env);
        Ok(())
    }

    /// Allowlist `address` until ledger `valid_until` (inclusive), for KYC or
    /// onboarding approvals that expire. Admin-only.
    ///
    /// The expiry is stored on the entry. `is_allowed` and transfers treat the
    /// address as allowlisted through ledger `valid_until` and as not
    /// allowlisted from ledger `valid_until + 1` onward. Returns
    /// `Err(InvalidInput)` if `valid_until` is already in the past.
    pub fn add_to_allowlist_until(
        env: Env,
        admin: Address,
        address: Address,
        valid_until: u32,
    ) -> Result<(), Error> {
        Self::add_to_allowlist(env, admin, address, Some(valid_until))
    }

    /// Add every address to the allowlist. Admin-only; each entry receives the
    /// same optional expiration ledger and an individual `AllowAdd` event.
    pub fn add_multiple_to_allowlist(
        env: Env,
        admin: Address,
        addresses: Vec<Address>,
        expiration_ledger: Option<u32>,
    ) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        if addresses.len() > MAX_BATCH_SIZE {
            return Err(Error::BatchTooLarge);
        }
        if let Some(expiration) = expiration_ledger {
            if expiration < env.ledger().sequence() {
                return Err(Error::InvalidInput);
            }
        }

        for address in addresses.iter() {
            Self::write_allowlist_entry(&env, &address, expiration_ledger, &admin);
            AllowAdd { address, by: admin.clone() }.publish(&env);
        }
        Ok(())
    }

    /// Add `address` to the allowlist using a signed off-chain authorization
    /// payload. This path verifies a nonce, a timestamp `expiry` and a
    /// `valid_until_ledger` bound before applying the allowlist change, so a
    /// relayer can submit it on behalf of the admin.
    ///
    /// Returns `Err(ExpiredSignature)` if `expiry` is not after the current
    /// ledger timestamp or the current ledger sequence is greater than
    /// `valid_until_ledger`. Both values are part of the signed payload, so a
    /// relayer cannot extend them.
    ///
    /// Returns `Err(ContractPaused)` if the contract is currently paused.
    pub fn add_to_allowlist_delegated(
        env: Env,
        admin: Address,
        address: Address,
        nonce: u64,
        expiry: u64,
        valid_until_ledger: u32,
        signature: BytesN<64>,
    ) -> Result<(), Error> {
        Self::reject_if_paused(&env)?;
        Self::require_configured_admin(&env, &admin)?;

        let now = env.ledger().timestamp();
        if expiry <= now {
            return Err(Error::ExpiredSignature);
        }
        if env.ledger().sequence() > valid_until_ledger {
            return Err(Error::ExpiredSignature);
        }

        let last_nonce: u64 = env
            .storage()
            .persistent()
            .get(&DataKey::DelegatedNonce(admin.clone()))
            .unwrap_or(0);
        if nonce <= last_nonce {
            return Err(Error::InvalidNonce);
        }

        let pubkey: BytesN<32> = env
            .storage()
            .instance()
            .get(&DataKey::DelegatedAdminPubKey)
            .ok_or(Error::DelegationNotConfigured)?;
        let action = Symbol::new(&env, "add_to_allowlist");
        let message = Self::delegated_action_message(
            &env,
            &address,
            &action,
            nonce,
            expiry,
            valid_until_ledger,
        );
        match soroban_sdk::env::internal::Env::verify_sig_ed25519(
            &env,
            pubkey.to_object(),
            message.to_object(),
            signature.to_object(),
        ) {
            Ok(_) => {}
            Err(_) => return Err(Error::NotAuthorized),
        }
        Self::write_allowlist_entry(&env, &address, None, &admin);
        AllowAdd { address, by: admin }.publish(&env);
        Ok(())
    }

    /// Remove `address` from the allowlist. Admin or compliance officer.
    ///
    /// If `address` is not allowlisted this is a silent no-op: no storage
    /// write happens and no `AllowRemove` event is emitted, so event streams
    /// only ever record real state changes.
    ///
    /// Returns `Err(ContractPaused)` if the contract is currently paused.
    pub fn remove_from_allowlist(env: Env, admin: Address, address: Address) -> Result<(), Error> {
        Self::reject_if_paused(&env)?;
        Self::require_compliance_authority(&env, &admin)?;
        Self::remove_allowed_if_present(&env, address, &admin);
        Ok(())
    }

    /// Remove every address from the allowlist. Admin or compliance officer;
    /// each address that was actually allowlisted emits an individual
    /// `AllowRemove` event. Addresses that are not allowlisted are skipped
    /// with no write and no event, matching `remove_from_allowlist`.
    ///
    /// Returns `Err(ContractPaused)` if the contract is currently paused.
    pub fn remove_multiple_from_allowlist(
        env: Env,
        admin: Address,
        addresses: Vec<Address>,
    ) -> Result<(), Error> {
        Self::reject_if_paused(&env)?;
        Self::require_compliance_authority(&env, &admin)?;
        if addresses.len() > MAX_BATCH_SIZE {
            return Err(Error::BatchTooLarge);
        }

        for address in addresses.iter() {
            Self::remove_allowed_if_present(&env, address, &admin);
        }
        Ok(())
    }

    /// Freeze `address` so it can neither send nor receive the wrapped token.
    /// Admin or compliance officer.
    ///
    /// Freezing is deliberately separate from allowlist removal: the
    /// address keeps its allowlist entry (including any expiration ledger),
    /// so an issuer can suspend a holder during an investigation and later
    /// restore them with `unfreeze` without re-onboarding. Freezing an
    /// already-frozen address is a no-op that still emits `AddressFrozen`.
    ///
    /// Returns `Err(ContractPaused)` if the contract is currently paused.
    pub fn freeze(env: Env, caller: Address, address: Address) -> Result<(), Error> {
        Self::reject_if_paused(&env)?;
        Self::require_compliance_authority(&env, &caller)?;
        let key = DataKey::Frozen(address.clone());
        env.storage().persistent().set(&key, &true);
        env.storage().persistent().extend_ttl(
            &key,
            ALLOWED_TTL_THRESHOLD,
            ALLOWED_TTL_EXTEND_TO,
        );
        AddressFrozen { caller, address }.publish(&env);
        Ok(())
    }

    /// Lift a freeze placed by `freeze`. Admin or compliance officer.
    ///
    /// The address's allowlist status is untouched. Unfreezing an address
    /// that is not frozen is a no-op that still emits `AddressUnfrozen`.
    ///
    /// Returns `Err(ContractPaused)` if the contract is currently paused.
    pub fn unfreeze(env: Env, caller: Address, address: Address) -> Result<(), Error> {
        Self::reject_if_paused(&env)?;
        Self::require_compliance_authority(&env, &caller)?;
        env.storage()
            .persistent()
            .remove(&DataKey::Frozen(address.clone()));
        AddressUnfrozen { caller, address }.publish(&env);
        Ok(())
    }

    /// Returns true if `address` is currently frozen.
    ///
    /// Not affected by pause state — reads always succeed.
    pub fn is_frozen(env: Env, address: Address) -> bool {
        Self::is_frozen_internal(&env, &address)
    }

    /// Claw back `amount` of the underlying token from `from`. Admin-only.
    ///
    /// Intended for court orders and error correction on real-world-asset
    /// tokens. The call is forwarded to the underlying token's SEP-41
    /// `clawback(from, amount)` (as exposed by the Stellar Asset Contract),
    /// so this contract must be the underlying token's admin and the asset
    /// must have clawback enabled.
    ///
    /// If `set_clawback_requires_freeze(admin, true)` has been called, `from`
    /// must be frozen first (see `freeze`), otherwise the call fails with
    /// `ClawbackRequiresFreeze`.
    ///
    /// Not blocked by pause, so legally mandated recoveries can still be
    /// executed during an incident. `amount` must be positive.
    ///
    /// Emits `Clawback { admin, from, amount }`.
    pub fn clawback(env: Env, admin: Address, from: Address, amount: i128) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        if amount <= 0 {
            return Err(Error::InvalidInput);
        }
        if Self::get_clawback_requires_freeze(env.clone()) && !Self::is_frozen_internal(&env, &from)
        {
            return Err(Error::ClawbackRequiresFreeze);
        }
        let token_address: Address = env
            .storage()
            .instance()
            .get(&DataKey::Token)
            .ok_or(Error::NotInitialized)?;
        let token_client = token::Client::new(&env, &token_address);
        let from_before = token_client.balance(&from);
        token::StellarAssetClient::new(&env, &token_address).clawback(&from, &amount);
        if from_before == amount {
            // `from` held exactly the clawed-back amount, so it is no longer a holder.
            let count = Self::read_holder_count(&env);
            env.storage()
                .instance()
                .set(&DataKey::HolderCount, &count.saturating_sub(1));
        }
        Clawback { admin, from, amount }.publish(&env);
        Ok(())
    }

    /// Number of addresses currently holding a non-zero balance of the wrapped
    /// token, as tracked by this contract.
    ///
    /// The counter follows movements made through `transfer` and `clawback`.
    /// Balances that change through any other path (for example direct transfers
    /// on the underlying token, or pre-existing balances from before deployment)
    /// are not reflected.
    pub fn holder_count(env: Env) -> u32 {
        Self::read_holder_count(&env)
    }

    /// Returns the configured holder cap, or `None` if unlimited.
    pub fn get_max_holders(env: Env) -> Option<u32> {
        Self::read_max_holders(&env)
    }

    /// Set (`Some(max)`) or clear (`None`) the cap on holders. Admin-only.
    ///
    /// Once set, a `transfer` that would move tokens to an address without a
    /// balance is rejected with `MaxHoldersReached` if it would push
    /// `holder_count` above `max`. Transfers between existing holders are never
    /// blocked by the cap. Lowering the cap below the current count does not
    /// remove holders; it only blocks new ones until the count falls.
    pub fn set_max_holders(env: Env, admin: Address, max: Option<u32>) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        match max {
            Some(max) => env.storage().instance().set(&DataKey::MaxHolders, &max),
            None => env.storage().instance().remove(&DataKey::MaxHolders),
        }
        Ok(())
    }

    /// Require (`true`) or stop requiring (`false`) that an address be frozen
    /// before it can be clawed back. Admin-only. Defaults to `false`.
    pub fn set_clawback_requires_freeze(
        env: Env,
        admin: Address,
        required: bool,
    ) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        env.storage()
            .instance()
            .set(&DataKey::ClawbackRequiresFreeze, &required);
        Ok(())
    }

    /// Returns whether `clawback` requires the target address to be frozen.
    pub fn get_clawback_requires_freeze(env: Env) -> bool {
        env.storage()
            .instance()
            .get(&DataKey::ClawbackRequiresFreeze)
            .unwrap_or(false)
    }

    /// Assign the compliance-officer role. Admin-only.
    ///
    /// Emits `ComplianceOfficerSet { admin, officer, previous }`.
    pub fn set_compliance_officer(env: Env, admin: Address, officer: Address) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        let previous: Option<Address> = env
            .storage()
            .instance()
            .get(&DataKey::ComplianceOfficer);
        env.storage()
            .instance()
            .set(&DataKey::ComplianceOfficer, &officer);
        ComplianceOfficerSet {
            admin,
            officer,
            previous,
        }
        .publish(&env);
        Ok(())
    }

    /// Revoke the compliance-officer role. Admin-only.
    ///
    /// Emits `ComplianceOfficerRevoked { admin, previous }`.
    pub fn revoke_compliance_officer(env: Env, admin: Address) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        let previous: Option<Address> = env
            .storage()
            .instance()
            .get(&DataKey::ComplianceOfficer);
        env.storage().instance().remove(&DataKey::ComplianceOfficer);
        ComplianceOfficerRevoked { admin, previous }.publish(&env);
        Ok(())
    }

    /// Returns the last-used delegated-action nonce for `admin`, or 0 if none
    /// has been used. A relayer should sign its next payload with a nonce
    /// strictly greater than this value.
    pub fn get_delegated_nonce(env: Env, admin: Address) -> u64 {
        env.storage()
            .persistent()
            .get(&DataKey::DelegatedNonce(admin))
            .unwrap_or(0)
    }

    /// Propose a new admin. The current admin remains active until the
    /// proposed admin calls `accept_admin`.
    pub fn propose_admin(
        env: Env,
        current_admin: Address,
        new_admin: Address,
    ) -> Result<(), Error> {
        Self::require_admin(&env, &current_admin)?;
        env.storage()
            .instance()
            .set(&DataKey::PendingAdmin, &new_admin);
        AdminProposed {
            current: current_admin,
            proposed: new_admin,
        }
        .publish(&env);
        Ok(())
    }

    /// Accept a pending admin transfer. Must be called by the proposed admin.
    pub fn accept_admin(env: Env, new_admin: Address) -> Result<(), Error> {
        Self::extend_instance_ttl(&env);
        new_admin.require_auth();

        let pending_admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::PendingAdmin)
            .ok_or(Error::NoPendingAdmin)?;
        if pending_admin != new_admin {
            return Err(Error::PendingAdminMismatch);
        }

        let old_admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(Error::NotInitialized)?;
        env.storage().instance().set(&DataKey::Admin, &new_admin);
        env.storage().instance().remove(&DataKey::PendingAdmin);
        AdminTransferred { old_admin, new_admin }.publish(&env);
        Ok(())
    }

    /// Immediately reassign the admin role to `new_admin`. Requires auth from
    /// `current_admin`, which must be the stored admin.
    ///
    /// Unlike `propose_admin` / `accept_admin`, this is single-step: the old
    /// admin loses all privileges as soon as this call succeeds, and any
    /// pending two-step proposal is cleared. Prefer the two-step flow when
    /// `new_admin`'s key has not yet been proven to work; use this one when
    /// the current key must be rotated out right away.
    ///
    /// Emits `AdminTransferred { old_admin, new_admin }`.
    pub fn transfer_admin(
        env: Env,
        current_admin: Address,
        new_admin: Address,
    ) -> Result<(), Error> {
        Self::require_admin(&env, &current_admin)?;
        env.storage().instance().set(&DataKey::Admin, &new_admin);
        env.storage().instance().remove(&DataKey::PendingAdmin);
        AdminTransferred {
            old_admin: current_admin,
            new_admin,
        }
        .publish(&env);
        Ok(())
    }

    /// Propose a two-step upgrade to `new_wasm_hash` (the hash of the
    /// already-uploaded replacement contract Wasm).
    ///
    /// Admin-only. The upgrade does **not** take effect immediately: it becomes
    /// committable only once the ledger sequence reaches `activated_at`, which
    /// `propose_upgrade` sets to `current_ledger + delay_ledgers`. This gives the
    /// admin, the compliance officer, and any external watchguard a
    /// `delay_ledgers`-long window to review the proposed Wasm and call
    /// `cancel_upgrade` before it can be installed — the safe "migration path"
    /// required by issue #113, in contrast to `jurisdiction-flag::upgrade`, which
    /// is single-step and issuer-only (see threat model J6).
    pub fn propose_upgrade(
        env: Env,
        admin: Address,
        new_wasm: BytesN<32>,
        delay_ledgers: u32,
    ) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        if delay_ledgers < MIN_UPGRADE_DELAY_LEDGERS {
            return Err(Error::UpgradeDelayTooShort);
        }
        let state = UpgradeState {
            new_wasm: new_wasm.clone(),
            activated_at: u64::from(env.ledger().sequence())
                .saturating_add(delay_ledgers as u64),
        };
        env.storage().instance().set(&DataKey::PendingUpgrade, &state);
        UpgradeProposed {
            admin,
            new_wasm,
            activated_at: state.activated_at,
        }
        .publish(&env);
        Ok(())
    }

    /// Commit a previously proposed upgrade, installing `new_wasm_hash`.
    ///
    /// Admin-only. Errors with `UpgradeNotReady` if no upgrade is pending or if
    /// the current ledger has not yet reached `activated_at`.
    pub fn commit_upgrade(env: Env, admin: Address) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        let state: UpgradeState = env
            .storage()
            .instance()
            .get(&DataKey::PendingUpgrade)
            .ok_or(Error::UpgradeNotReady)?;
        if u64::from(env.ledger().sequence()) < state.activated_at {
            return Err(Error::UpgradeNotReady);
        }
        env.deployer()
            .update_current_contract_wasm(state.new_wasm.clone());
        env.storage().instance().remove(&DataKey::PendingUpgrade);
        UpgradeCommitted {
            admin,
            new_wasm: state.new_wasm,
        }
        .publish(&env);
        Ok(())
    }

    /// Cancel a pending upgrade. Admin-only.
    pub fn cancel_upgrade(env: Env, admin: Address) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        env.storage().instance().remove(&DataKey::PendingUpgrade);
        UpgradeCancelled { admin }.publish(&env);
        Ok(())
    }

    /// Return the pending admin proposal, if one exists.
    pub fn get_pending_admin(env: Env) -> Option<Address> {
        env.storage().instance().get(&DataKey::PendingAdmin)
    }

    /// Return the pending upgrade and activation ledger, if one exists.
    pub fn get_pending_upgrade(env: Env) -> Option<UpgradeState> {
        env.storage().instance().get(&DataKey::PendingUpgrade)
    }

    /// Current on-chain schema version (see [`SCHEMA_VERSION`]).
    pub fn schema_version(_env: Env) -> u32 {
        SCHEMA_VERSION
    }

    /// Returns true if `address` is currently allowlisted.
    ///
    /// Not affected by pause state — reads always succeed. This view does not
    /// extend the entry's TTL; transfer checks refresh existing entries when
    /// their remaining TTL falls below the configured threshold.
    pub fn is_allowed(env: Env, address: Address) -> bool {
        Self::extend_instance_ttl(&env);
        let entry: Option<AllowlistEntry> =
            env.storage().persistent().get(&DataKey::Allowed(address));
        match entry {
            None => false,
            Some(entry) => Self::entry_is_active(&env, &entry),
        }
    }

    /// Batch form of [`is_allowed`]: returns one `bool` per input address, in
    /// the same order. Accepts at most [`MAX_BATCH_SIZE`] addresses and
    /// returns `Err(BatchTooLarge)` otherwise, so integrators can check many
    /// holders in a single call.
    ///
    /// Not affected by pause state — reads always succeed. Like `is_allowed`,
    /// it does not extend entry TTLs.
    pub fn is_allowed_batch(env: Env, addresses: Vec<Address>) -> Result<Vec<bool>, Error> {
        if addresses.len() > MAX_BATCH_SIZE {
            return Err(Error::BatchTooLarge);
        }
        let mut results = Vec::new(&env);
        for address in addresses.iter() {
            results.push_back(Self::is_allowed(env.clone(), address));
        }
        Ok(results)
    }

    /// Returns the allowlist entry for `address`, if any, including who
    /// approved it (`added_by`) and at which ledger (`added_at_ledger`).
    ///
    /// Provenance is `None` for entries approved before it was recorded.
    /// An already-expired entry is still returned here (it is only ignored,
    /// not deleted) — use `is_allowed` for the effective status.
    pub fn get_allowlist_entry(env: Env, address: Address) -> Option<AllowlistEntryInfo> {
        let entry: AllowlistEntry = env
            .storage()
            .persistent()
            .get(&DataKey::Allowed(address.clone()))?;
        let provenance: Option<AllowlistProvenance> = env
            .storage()
            .persistent()
            .get(&DataKey::AllowedProvenance(address));
        Some(AllowlistEntryInfo {
            expiration_ledger: entry.expiration_ledger,
            added_by: provenance.as_ref().map(|p| p.added_by.clone()),
            added_at_ledger: provenance.map(|p| p.added_at_ledger),
        })
    }

    /// Number of addresses that currently hold an allowlist entry.
    ///
    /// Maintained incrementally: it changes only when an add creates a new
    /// entry or a remove deletes an existing one. Re-adding an address (for
    /// example to change its expiration) and removing an address that is not
    /// listed leave it unchanged. Like `get_allowlist_entry`, it counts stored
    /// entries whether or not they have expired; use `is_allowed` for the
    /// effective status of one address.
    pub fn allowlist_count(env: Env) -> u32 {
        env.storage()
            .instance()
            .get(&DataKey::AllowlistCount)
            .unwrap_or(0)
    }

    /// Set or clear the global maximum balance any single address may hold.
    /// Admin-only. `None` removes the limit. Negative limits are rejected
    /// with `InvalidInput`.
    ///
    /// Enforced on the recipient of `transfer` and `transfer_with_proof`
    /// (see `MaxBalanceExceeded`). Emits `MaxBalanceSet`.
    pub fn set_global_max_balance(env: Env, admin: Address, limit: Option<i128>) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        Self::validate_limit(limit)?;
        match limit {
            Some(limit) => env
                .storage()
                .instance()
                .set(&DataKey::GlobalMaxBalance, &limit),
            None => env.storage().instance().remove(&DataKey::GlobalMaxBalance),
        }
        MaxBalanceSet {
            admin,
            address: None,
            limit,
        }
        .publish(&env);
        Ok(())
    }

    /// Set or clear the maximum balance for one address. Admin-only. `None`
    /// removes the per-address limit. Negative limits are rejected with
    /// `InvalidInput`.
    ///
    /// When both a global and a per-address limit apply, the stricter one is
    /// enforced. Emits `MaxBalanceSet`.
    pub fn set_address_max_balance(
        env: Env,
        admin: Address,
        address: Address,
        limit: Option<i128>,
    ) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        Self::validate_limit(limit)?;
        let key = DataKey::MaxBalance(address.clone());
        match limit {
            Some(limit) => {
                env.storage().persistent().set(&key, &limit);
                env.storage()
                    .persistent()
                    .extend_ttl(&key, ALLOWED_TTL_THRESHOLD, ALLOWED_TTL_EXTEND_TO);
            }
            None => env.storage().persistent().remove(&key),
        }
        MaxBalanceSet {
            admin,
            address: Some(address),
            limit,
        }
        .publish(&env);
        Ok(())
    }

    /// Returns the global maximum balance, if one is set.
    pub fn get_global_max_balance(env: Env) -> Option<i128> {
        env.storage().instance().get(&DataKey::GlobalMaxBalance)
    }

    /// Returns the per-address maximum balance for `address`, if one is set.
    pub fn get_address_max_balance(env: Env, address: Address) -> Option<i128> {
        env.storage().persistent().get(&DataKey::MaxBalance(address))
    }

    /// Publish the Merkle root of the proof-based allowlist. Admin-only.
    ///
    /// Proof mode lets an issuer authorize a large holder set with one
    /// on-chain value. Holders prove membership with [`is_allowed_with_proof`]
    /// or [`transfer_with_proof`]. The root must be built with the leaf and
    /// node encoding in `docs/allowlist-merkle-root.md`.
    ///
    /// Proof mode has no per-address expiration and no per-address revocation:
    /// to remove a holder, publish a new root that omits them. Replacing the
    /// root does not touch on-chain entries used by `is_allowed` / `transfer`.
    ///
    /// Returns `Err(ContractPaused)` if the contract is paused.
    /// Emits `AllowlistRootSet { admin, root }`.
    pub fn set_allowlist_root(env: Env, admin: Address, root: BytesN<32>) -> Result<(), Error> {
        Self::reject_if_paused(&env)?;
        Self::require_admin(&env, &admin)?;
        env.storage().instance().set(&DataKey::AllowlistRoot, &root);
        AllowlistRootSet { admin, root }.publish(&env);
        Ok(())
    }

    /// Returns the current proof-mode allowlist root, if one has been set.
    pub fn get_allowlist_root(env: Env) -> Option<BytesN<32>> {
        env.storage().instance().get(&DataKey::AllowlistRoot)
    }

    /// Returns true if `proof` shows that `address` is a leaf under the
    /// current allowlist root.
    ///
    /// Returns false when no root is set, when `proof` has more than
    /// [`MAX_MERKLE_PROOF_LEN`] entries, or when the proof does not rebuild
    /// the root. Not affected by pause state, and does not check freeze
    /// status (see `is_frozen`).
    pub fn is_allowed_with_proof(env: Env, address: Address, proof: Vec<BytesN<32>>) -> bool {
        Self::verify_allowlist_proof(&env, &address, &proof)
    }

    /// Proof-mode counterpart of [`transfer`]. Each party proves membership
    /// under the current root instead of using the on-chain allowlist.
    ///
    /// Returns `Err(ContractPaused)` if the contract is paused, and
    /// `Err(AddressFrozen)` if either party is frozen. Returns `Ok(false)`
    /// without forwarding if either proof fails, emitting `Blocked`. Otherwise
    /// forwards the transfer to the underlying token and returns `Ok(true)`.
    pub fn transfer_with_proof(
        env: Env,
        from: Address,
        to: Address,
        amount: i128,
        from_proof: Vec<BytesN<32>>,
        to_proof: Vec<BytesN<32>>,
    ) -> Result<bool, Error> {
        Self::extend_instance_ttl(&env);
        if amount < 0 {
            return Err(Error::InvalidInput);
        }
        if Self::is_paused(env.clone()) {
            return Err(Error::ContractPaused);
        }
        from.require_auth();
        if Self::is_frozen_internal(&env, &from) || Self::is_frozen_internal(&env, &to) {
            return Err(Error::AddressFrozen);
        }
        if !Self::verify_allowlist_proof(&env, &from, &from_proof)
            || !Self::verify_allowlist_proof(&env, &to, &to_proof)
        {
            Blocked { from, to, amount }.publish(&env);
            return Ok(false);
        }
        Self::enforce_max_balance(&env, &to, amount)?;
        let token_address: Address = env
            .storage()
            .instance()
            .get(&DataKey::Token)
            .ok_or(Error::NotInitialized)?;
        token::Client::new(&env, &token_address).transfer(&from, &to, &amount);
        Ok(true)
    }

    /// Version of the shared `ComplianceCheck` interface implemented by this
    /// contract. Callers should read this once and refuse to call
    /// `is_compliant` if it does not match the version they were built
    /// against (see [`COMPLIANCE_CHECK_INTERFACE_VERSION`]).
    pub fn interface_version(_env: Env) -> u32 {
        COMPLIANCE_CHECK_INTERFACE_VERSION
    }

    /// Unified compliance check — returns a [`CheckResult`] describing
    /// whether `address` may transact and, if not, why.
    ///
    /// This entry point implements the shared `ComplianceCheck` interface
    /// (`is_compliant(address) -> CheckResult`) so external contracts can call
    /// any of the three compliance primitives through the same pattern.
    ///
    /// Reason codes:
    /// - [`CHECK_CODE_ALLOWED`] (0): `address` is on the allowlist.
    /// - [`CHECK_CODE_NOT_ALLOWLISTED`] (1): `address` has no allowlist entry.
    /// - [`CHECK_CODE_ALLOWLIST_ENTRY_EXPIRED`] (2): `address` has an
    ///   allowlist entry, but its `expiration_ledger` has passed.
    ///
    /// Not affected by pause state — reads always succeed.
    pub fn is_compliant(env: Env, address: Address) -> CheckResult {
        Self::extend_instance_ttl(&env);
        match env
            .storage()
            .persistent()
            .get::<DataKey, AllowlistEntry>(&DataKey::Allowed(address))
        {
            None => CheckResult {
                allowed: false,
                code: CHECK_CODE_NOT_ALLOWLISTED,
            },
            Some(AllowlistEntry {
                expiration_ledger: None,
            }) => CheckResult {
                allowed: true,
                code: CHECK_CODE_ALLOWED,
            },
            Some(AllowlistEntry {
                expiration_ledger: Some(exp),
            }) => {
                if env.ledger().sequence() <= exp {
                    CheckResult {
                        allowed: true,
                        code: CHECK_CODE_ALLOWED,
                    }
                } else {
                    CheckResult {
                        allowed: false,
                        code: CHECK_CODE_ALLOWLIST_ENTRY_EXPIRED,
                    }
                }
            }
        }
    }

    /// Pause all mutating operations. Admin-only.
    ///
    /// While paused:
    /// - `transfer` returns `Err(ContractPaused)`.
    /// - `add_to_allowlist`, `add_to_allowlist_delegated`,
    ///   `remove_from_allowlist`, and `remove_multiple_from_allowlist` return
    ///   `Err(ContractPaused)`.
    ///
    /// The following are deliberately **not** blocked by pause so that an
    /// operator can always recover from an incident:
    /// - `unpause` — to resume normal operation.
    /// - `propose_admin` / `accept_admin` / `transfer_admin` — to rotate a
    ///   compromised key.
    /// - `set_compliance_officer` / `revoke_compliance_officer`.
    /// - Read-only functions (`is_allowed`, `is_paused`, `metadata`, …).
    pub fn pause(env: Env, admin: Address) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        env.storage().instance().set(&DataKey::Paused, &true);
        Paused {
            admin: admin.clone(),
        }
        .publish(&env);
        Ok(())
    }

    /// Unpause. Admin-only.
    pub fn unpause(env: Env, admin: Address) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        env.storage().instance().set(&DataKey::Paused, &false);
        Unpaused {
            admin: admin.clone(),
        }
        .publish(&env);
        Ok(())
    }

    /// Returns true if the contract is currently paused.
    pub fn is_paused(env: Env) -> bool {
        env.storage()
            .instance()
            .get(&DataKey::Paused)
            .unwrap_or(false)
    }

    /// Transfer `amount` of the underlying token from `from` to `to`.
    ///
    /// Returns `Err(AddressFrozen)` if either party is frozen (see `freeze`).
    ///
    /// Returns `Ok(false)` without forwarding if either party is not
    /// allowlisted, emitting a `Blocked` event for auditability. Checking an
    /// existing allowlist entry extends its TTL when it falls below the
    /// configured threshold.
    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) -> Result<bool, Error> {
        Self::extend_instance_ttl(&env);
        if amount < 0 {
            return Err(Error::InvalidInput);
        }

        if Self::is_paused(env.clone()) {
            return Err(Error::ContractPaused);
        }

        from.require_auth();

        if Self::is_frozen_internal(&env, &from) || Self::is_frozen_internal(&env, &to) {
            return Err(Error::AddressFrozen);
        }

        let from_allowed = Self::is_allowed_and_extend_ttl(&env, from.clone());
        let to_allowed = Self::is_allowed_and_extend_ttl(&env, to.clone());
        if !from_allowed || !to_allowed {
            Blocked { from, to, amount }.publish(&env);
            return Ok(false);
        }
        Self::enforce_max_balance(&env, &to, amount)?;

        let token_address: Address = env
            .storage()
            .instance()
            .get(&DataKey::Token)
            .ok_or(Error::NotInitialized)?;
        let token_client = token::Client::new(&env, &token_address);

        // Holder accounting: read balances before and after the move so the
        // counter reflects 0 -> non-zero and non-zero -> 0 transitions.
        let from_before = token_client.balance(&from);
        let to_before = token_client.balance(&to);
        let (leaves, joins) =
            Self::holder_transition(&from, &to, amount, from_before, to_before);
        let count = Self::read_holder_count(&env);
        let new_count = count.saturating_add(joins as u32).saturating_sub(leaves as u32);
        if joins {
            if let Some(max) = Self::read_max_holders(&env) {
                if new_count > max {
                    return Err(Error::MaxHoldersReached);
                }
            }
        }

        token_client.transfer(&from, &to, &amount);
        env.storage().instance().set(&DataKey::HolderCount, &new_count);
        Ok(true)
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------


    /// Extends the instance entry TTL. Soroban does not extend instance TTL
    /// implicitly on invocation, so every write path calls this explicitly.
    fn extend_instance_ttl(env: &Env) {
        env.storage()
            .instance()
            .extend_ttl(INSTANCE_TTL_THRESHOLD, INSTANCE_TTL_EXTEND_TO);
    }
    fn require_admin(env: &Env, admin: &Address) -> Result<(), Error> {
        admin.require_auth();
        Self::require_configured_admin(env, admin)
    }

    fn require_configured_admin(env: &Env, admin: &Address) -> Result<(), Error> {
        Self::extend_instance_ttl(&env);
        let stored_admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(Error::NotInitialized)?;
        if stored_admin != *admin {
            return Err(Error::NotAuthorized);
        }
        Ok(())
    }

    /// Accept either the stored admin or the stored compliance officer.
    fn require_compliance_authority(env: &Env, caller: &Address) -> Result<(), Error> {
        caller.require_auth();
        let stored_admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(Error::NotInitialized)?;
        if stored_admin == *caller {
            return Ok(());
        }
        let officer: Option<Address> = env.storage().instance().get(&DataKey::ComplianceOfficer);
        if officer.as_ref() == Some(caller) {
            return Ok(());
        }
        Err(Error::NotAuthorized)
    }

    /// Stores `entry` for `address` and extends its TTL. `AllowlistCount` is
    /// incremented only when the address had no stored entry before, so
    /// updating an existing entry leaves the count unchanged.
    fn store_allowlist_entry(env: &Env, address: &Address, entry: AllowlistEntry) {
        let key = DataKey::Allowed(address.clone());
        let is_new = !env.storage().persistent().has(&key);
        env.storage().persistent().set(&key, &entry);
        env.storage()
            .persistent()
            .extend_ttl(&key, ALLOWED_TTL_THRESHOLD, ALLOWED_TTL_EXTEND_TO);
        if is_new {
            Self::adjust_allowlist_count(env, 1);
        }
    }

    /// Deletes `address`'s allowlist entry. `AllowlistCount` is decremented
    /// only when an entry was actually present.
    fn remove_allowlist_entry(env: &Env, address: &Address) {
        let key = DataKey::Allowed(address.clone());
        if env.storage().persistent().has(&key) {
            env.storage().persistent().remove(&key);
            Self::adjust_allowlist_count(env, -1);
        }
    }

    fn adjust_allowlist_count(env: &Env, delta: i64) {
        let current: u32 = env
            .storage()
            .instance()
            .get(&DataKey::AllowlistCount)
            .unwrap_or(0);
        let updated = (i64::from(current) + delta).max(0) as u32;
        env.storage()
            .instance()
            .set(&DataKey::AllowlistCount, &updated);
    }

    fn validate_limit(limit: Option<i128>) -> Result<(), Error> {
        match limit {
            Some(value) if value < 0 => Err(Error::InvalidInput),
            _ => Ok(()),
        }
    }

    /// Rejects a transfer that would leave `to` above its effective maximum
    /// balance: the stricter of the global limit and `to`'s own limit, using
    /// whichever are set. Does nothing when neither is set.
    fn enforce_max_balance(env: &Env, to: &Address, amount: i128) -> Result<(), Error> {
        let global: Option<i128> = env.storage().instance().get(&DataKey::GlobalMaxBalance);
        let per_address: Option<i128> = env
            .storage()
            .persistent()
            .get(&DataKey::MaxBalance(to.clone()));
        let limit = match (global, per_address) {
            (None, None) => return Ok(()),
            (Some(limit), None) | (None, Some(limit)) => limit,
            (Some(global), Some(own)) => global.min(own),
        };
        let token_address: Address = env
            .storage()
            .instance()
            .get(&DataKey::Token)
            .ok_or(Error::NotInitialized)?;
        let current = token::Client::new(env, &token_address).balance(to);
        let projected = current.checked_add(amount).ok_or(Error::InvalidInput)?;
        if projected > limit {
            return Err(Error::MaxBalanceExceeded);
        }
        Ok(())
    }

    /// Rebuilds the root from `address`'s leaf and the supplied siblings and
    /// compares it with the stored root.
    fn verify_allowlist_proof(env: &Env, address: &Address, proof: &Vec<BytesN<32>>) -> bool {
        let root: BytesN<32> = match env.storage().instance().get(&DataKey::AllowlistRoot) {
            Some(root) => root,
            None => return false,
        };
        if proof.len() > MAX_MERKLE_PROOF_LEN {
            return false;
        }
        let mut node = Self::merkle_leaf_hash(env, address);
        for sibling in proof.iter() {
            node = Self::merkle_node_hash(env, &node, &sibling);
        }
        node == root
    }

    /// Leaf hash: `sha256(0x00 || address_strkey)`. The `0x00` prefix keeps
    /// leaves and internal nodes in separate domains.
    fn merkle_leaf_hash(env: &Env, address: &Address) -> BytesN<32> {
        let address_str = address.to_string().to_string();
        let mut preimage = Bytes::from_slice(env, &[0x00]);
        preimage.append(&Bytes::from_slice(env, address_str.as_bytes()));
        env.crypto().sha256(&preimage).to_bytes()
    }

    /// Internal node hash: `sha256(0x01 || min(a, b) || max(a, b))`. Sorting
    /// the pair makes proofs independent of left/right position.
    fn merkle_node_hash(env: &Env, a: &BytesN<32>, b: &BytesN<32>) -> BytesN<32> {
        let (lo, hi) = if a.to_array() <= b.to_array() {
            (a, b)
        } else {
            (b, a)
        };
        let mut preimage = Bytes::from_slice(env, &[0x01]);
        preimage.append(&Bytes::from_slice(env, &lo.to_array()));
        preimage.append(&Bytes::from_slice(env, &hi.to_array()));
        env.crypto().sha256(&preimage).to_bytes()
    }

    fn is_frozen_internal(env: &Env, address: &Address) -> bool {
        env.storage()
            .persistent()
            .get(&DataKey::Frozen(address.clone()))
            .unwrap_or(false)
    }

    /// An entry is active unless it has an expiration ledger that is already
    /// in the past (`current sequence > expiration_ledger`).
    fn entry_is_active(env: &Env, entry: &AllowlistEntry) -> bool {
        match entry.expiration_ledger {
            None => true,
            Some(exp) => env.ledger().sequence() <= exp,
        }
    }

    /// Returns whether `address` has an active (non-expired) allowlist entry.
    /// Refreshes the entry's TTL when it is active.
    fn is_allowed_and_extend_ttl(env: &Env, address: Address) -> bool {
        let address_for_provenance = address.clone();
        let key = DataKey::Allowed(address);
        let entry: Option<AllowlistEntry> = env.storage().persistent().get(&key);
        match entry {
            Some(entry) if Self::entry_is_active(env, &entry) => {
                Self::extend_allowed_ttl(env, &key);
                let provenance_key = DataKey::AllowedProvenance(address_for_provenance);
                if env.storage().persistent().has(&provenance_key) {
                    Self::extend_allowed_ttl(env, &provenance_key);
                }
                true
            }
            _ => false,
        }
    }

    /// Writes the allowlist entry and its provenance, then extends both TTLs.
    fn write_allowlist_entry(
        env: &Env,
        address: &Address,
        expiration_ledger: Option<u32>,
        added_by: &Address,
    ) {
        let key = DataKey::Allowed(address.clone());
        Self::store_allowlist_entry(env, address, AllowlistEntry { expiration_ledger });
        let provenance_key = DataKey::AllowedProvenance(address.clone());
        env.storage().persistent().set(
            &provenance_key,
            &AllowlistProvenance {
                added_by: added_by.clone(),
                added_at_ledger: env.ledger().sequence(),
            },
        );
        Self::extend_allowed_ttl(env, &key);
        Self::extend_allowed_ttl(env, &provenance_key);
    }

    fn extend_allowed_ttl(env: &Env, key: &DataKey) {
        env.storage()
            .persistent()
            .extend_ttl(key, ALLOWED_TTL_THRESHOLD, ALLOWED_TTL_EXTEND_TO);
    }

    /// Removes the allowlist entry for `address` and emits `AllowRemove`, but
    /// only if an entry exists. Absent addresses are left untouched.
    fn remove_allowed_if_present(env: &Env, address: Address, by: &Address) {
        let key = DataKey::Allowed(address.clone());
        if env.storage().persistent().has(&key) {
            Self::remove_allowlist_entry(env, &address);
            env.storage()
                .persistent()
                .remove(&DataKey::AllowedProvenance(address.clone()));
            AllowRemove {
                address,
                by: by.clone(),
            }
            .publish(env);
        }
    }

    fn read_holder_count(env: &Env) -> u32 {
        env.storage()
            .instance()
            .get(&DataKey::HolderCount)
            .unwrap_or(0)
    }

    fn read_max_holders(env: &Env) -> Option<u32> {
        env.storage().instance().get(&DataKey::MaxHolders)
    }

    /// Returns `(leaves, joins)`: whether `from` ends the move with a zero balance
    /// and whether `to` starts the move with a zero balance. A self-transfer or a
    /// zero-amount move changes no holder.
    fn holder_transition(
        from: &Address,
        to: &Address,
        amount: i128,
        from_before: i128,
        to_before: i128,
    ) -> (bool, bool) {
        if amount <= 0 || from == to {
            return (false, false);
        }
        (from_before == amount, to_before == 0)
    }

    fn reject_if_paused(env: &Env) -> Result<(), Error> {
        if env
            .storage()
            .instance()
            .get(&DataKey::Paused)
            .unwrap_or(false)
        {
            return Err(Error::ContractPaused);
        }
        Ok(())
    }

    /// Message signed by the delegated admin key:
    /// `allowlist-delegated-v2:<target>:<action>:<nonce>:<expiry>:<valid_until_ledger>`.
    fn delegated_action_message(
        env: &Env,
        target: &Address,
        action: &Symbol,
        nonce: u64,
        expiry: u64,
        valid_until_ledger: u32,
    ) -> Bytes {
        let mut message = Bytes::new(env);
        message.append(&Bytes::from_slice(env, b"allowlist-delegated-v2:"));
        let target_str = target.to_string().to_string();
        message.append(&Bytes::from_slice(env, target_str.as_bytes()));
        message.push_back(b':');
        let action_str = action.to_string().to_string();
        message.append(&Bytes::from_slice(env, action_str.as_bytes()));
        message.push_back(b':');
        let nonce_str = alloc::format!("{nonce}");
        message.append(&Bytes::from_slice(env, nonce_str.as_bytes()));
        message.push_back(b':');
        let expiry_str = alloc::format!("{expiry}");
        message.append(&Bytes::from_slice(env, expiry_str.as_bytes()));
        message.push_back(b':');
        let valid_until_str = alloc::format!("{valid_until_ledger}");
        message.append(&Bytes::from_slice(env, valid_until_str.as_bytes()));
        message
    }
}

#[cfg(test)]
mod test;
#[cfg(test)]
mod fuzz_test;
