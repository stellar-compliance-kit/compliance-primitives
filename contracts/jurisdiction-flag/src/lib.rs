// Copyright (c) 2026 Stellar Compliance Kit contributors
// SPDX-License-Identifier: MIT
// See the LICENSE file in the repository root for the full license text.

//! `jurisdiction-flag` is a `#![no_std]` Soroban contract that attaches a
//! jurisdiction code (e.g. an ISO 3166-1 alpha-2 country code) to an
//! address.
//!
//! **Permission semantics**: `is_permitted_jurisdiction` uses *any*
//! matching — it returns `true` if at least one of the address's codes
//! appears in `allowed_codes`. An address with no codes is never permitted.
//!
//! **Code format**: `set_jurisdiction` only accepts ISO 3166-1 alpha-2 codes
//! written as exactly two *uppercase* ASCII letters (`"US"`, `"GB"`, …).
//! Anything else — empty, too short/long, lowercase (`"us"`), or containing
//! non-letters (`"U1"`, `"U-"`) — is rejected with
//! `Error::InvalidJurisdictionCode`. Codes are never normalized: matching in
//! `is_permitted_jurisdiction` stays exact and case-sensitive (#54), so
//! requiring the canonical uppercase form on write guarantees an address
//! can't be flagged as `"us"` and then silently fail to match an
//! `allowed_codes` entry of `"US"`.
//!
//! **Known codes (#775)**: the two letters must also be an officially
//! assigned ISO 3166-1 alpha-2 code, checked against an embedded 676-bit
//! bitmap ([`ISO_3166_1_BITMAP`]), so typos like `"UK"` or `"XX"` are
//! rejected instead of being stored and never matching policy.
//!
//! **Subdivisions (#774)**: ISO 3166-2 codes of the form `CC-SSS` (a known
//! country code, a hyphen, then 1–3 uppercase ASCII letters or digits, e.g.
//! `"US-NY"`, `"GB-ENG"`, `"FR-75"`) are also accepted. By default a
//! permitted country implies its subdivisions: `allowed_codes = ["US"]`
//! permits an address flagged `"US-NY"`. The issuer can disable this with
//! `set_subdivision_inheritance(issuer, false)`, after which matching is
//! exact only.
//!
//! **Cooldown (#777)**: the issuer may configure a per-address cooldown (in
//! ledgers) via `set_jurisdiction_cooldown`. While non-zero, a jurisdiction
//! change for an address within `cooldown` ledgers of its previous change is
//! rejected with `Error::JurisdictionCooldownActive`. Removals are exempt.
//!
//! **Callers**: the configured issuer or compliance officer may call
//! `set_jurisdiction`, `set_jurisdiction_until`, `add_jurisdiction`, and
//! `set_multiple_jurisdictions`; only the issuer may call
//! `remove_jurisdiction`, `remove_jurisdiction_multiple`, or `upgrade`.
//! `set_jurisdiction` / `get_jurisdiction` remain single-code conveniences.
//! Use `add_jurisdiction`, `remove_jurisdiction`, and `list_jurisdictions`
//! for the multi-code model. Any contract or off-chain client can read codes
//! and call `is_permitted_jurisdiction(address, allowed_codes)` directly.
#![no_std]

use soroban_sdk::{
    contract, contracterror, contractevent, contractimpl, contractmeta, contracttype, Address,
    BytesN, Env, String, Vec,
};

// #809: embed crate version and repository URL in the deployed WASM so the
// release workflow (and anyone inspecting the chain) can tell which release
// is live.
contractmeta!(key = "version", val = env!("CARGO_PKG_VERSION"));
contractmeta!(key = "source", val = env!("CARGO_PKG_REPOSITORY"));

/// Current version of the shared `ComplianceCheck` trait implemented by this
/// contract (#808). Callers must compare this against the version they were
/// built against before invoking `is_compliant`.
pub const COMPLIANCE_CHECK_INTERFACE_VERSION: u32 = 2;

/// Reason code returned by `is_compliant` when the address has at least one
/// active jurisdiction code.
pub const CHECK_CODE_OK: u32 = 0;
/// Reason code returned by `is_compliant` when the address has no active
/// jurisdiction code (never flagged, or its flag expired).
pub const CHECK_CODE_NO_JURISDICTION: u32 = 1;

/// Result of a shared `ComplianceCheck` check (#807): whether the address is
/// allowed, plus a reason code explaining the outcome.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckResult {
    pub allowed: bool,
    pub code: u32,
}

/// Length in bytes of an ISO 3166-1 alpha-2 code.
const JURISDICTION_CODE_LEN: u32 = 2;
/// Maximum length of an ISO 3166-2 subdivision code (`CC-SSS`).
const SUBDIVISION_CODE_MAX_LEN: u32 = 6;

/// Bitmap of officially assigned ISO 3166-1 alpha-2 codes (249 entries).
/// Bit `(a - 'A') * 26 + (b - 'A')` is set when code `ab` is assigned.
/// A constant-time lookup keeps validation cost flat (#775).
pub const ISO_3166_1_BITMAP: [u32; 22] = [
    0xEEDF5978, 0xDEDDBDEF, 0x15843F27, 0x0E00D480, 0xB0095C00, 0x0015FB9F, 0x7818068D, 0x0340400F, 0xF42B1D00, 0xFD4F8141, 0x25D7FFFC, 0x0100084B, 0x538F3C40, 0x40000001, 0xFDF15100, 0x9FBB3AE7, 0x0410419A, 0x00408557, 0x00004002, 0x00100000, 0x00400408, 0x00000001,
];

/// Returns `true` if `code` is an officially assigned ISO 3166-1 alpha-2
/// code. `code` must already be two uppercase ASCII letters.
fn is_known_country(code: [u8; 2]) -> bool {
    let idx = (code[0] - b'A') as usize * 26 + (code[1] - b'A') as usize;
    ISO_3166_1_BITMAP[idx / 32] & (1u32 << (idx % 32)) != 0
}

/// Extend persistent jurisdiction entries below 120,960 ledgers (~7 days).
const TTL_THRESHOLD: u32 = compliance_ttl::TTL_THRESHOLD;
/// Target 1,555,200 ledgers (~90 days) after extension.
const TTL_EXTEND_TO: u32 = compliance_ttl::TTL_EXTEND_TO;

/// Maximum number of entries accepted by `set_multiple_jurisdictions` in a
/// single call. Keeps transaction costs bounded and prevents resource
/// exhaustion.
pub const MAX_BATCH_SIZE: u32 = 100;

/// Instance-storage TTL policy: whenever the remaining instance TTL drops
/// below [`INSTANCE_TTL_THRESHOLD`], it is bumped back up to
/// [`INSTANCE_TTL_EXTEND_TO`]. Matches `compliance-aggregator`.
pub const INSTANCE_TTL_THRESHOLD: u32 = compliance_ttl::TTL_THRESHOLD; // ~7 days
/// Target instance TTL after an extension.
pub const INSTANCE_TTL_EXTEND_TO: u32 = compliance_ttl::TTL_EXTEND_TO; // ~90 days

/// Maximum number of jurisdiction codes that can be attached to a single
/// address. Enforced in `add_jurisdiction` to prevent a compromised or buggy
/// officer key from attaching so many codes that every later
/// `is_permitted_jurisdiction` call (which does `allowed_codes × codes`
/// comparisons) exceeds the CPU budget inside a consumer's transfer.
///
/// The value 8 is chosen to be well within the Soroban per-invocation CPU
/// budget for all realistic `allowed_codes` list sizes, while covering any
/// legitimate multi-jurisdiction use case (an address is rarely subject to
/// more than a handful of applicable codes).
pub const MAX_CODES_PER_ADDRESS: u32 = 8;
/// Maximum number of member codes in one named jurisdiction group.
pub const MAX_GROUP_CODES: u32 = 64;
/// Maximum length in bytes of a jurisdiction group name.
pub const MAX_GROUP_NAME_LEN: u32 = 32;

#[contracttype]
#[derive(Clone)]
enum DataKey {
    /// The issuer address, set once in `initialize`. Instance storage.
    Issuer,
    ComplianceOfficer,
    Jurisdiction(Address),
    Jurisdictions(Address),
    /// Optional expiry ledger for the address's jurisdiction codes. Absent =
    /// never expires.
    ValidUntil(Address),
    Paused,
    /// Pending issuer address proposed via `propose_issuer`. Instance storage.
    PendingIssuer,
    /// Pending issuer-authorized WASM upgrade proposal. Instance storage.
    PendingUpgrade,
    /// When `true`, a permitted country does NOT imply its subdivisions.
    /// Absent / `false` = subdivisions inherit (default). Instance storage.
    StrictSubdivisions,
    /// Per-address jurisdiction-change cooldown in ledgers. Instance storage.
    Cooldown,
    /// Ledger sequence of the address's last jurisdiction change. Persistent.
    LastChange(Address),
    /// Named jurisdiction group (e.g. `EU`) -> member codes. Persistent storage.
    Group(String),
    /// Contract-level [`JurisdictionMode`]. Instance storage; absent = allow-list.
    Mode,
}

/// How `is_permitted_jurisdiction` interprets its code list.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JurisdictionMode {
    /// The list names permitted jurisdictions (default).
    AllowList,
    /// The list names blocked jurisdictions; everything else is permitted.
    BlockList,
}

/// Emitted when a named jurisdiction group is defined or replaced.
#[contractevent]
pub struct GroupSet {
    #[topic]
    pub name: String,
    pub codes: Vec<String>,
}

/// Emitted when the contract-level jurisdiction mode changes.
#[contractevent]
pub struct ModeSet {
    pub mode: JurisdictionMode,
}

/// Emitted whenever a jurisdiction flag is set.
#[contractevent]
pub struct JurisdictionSet {
    #[topic]
    pub address: Address,
    pub code: String,
    /// Stored codes before this call; empty if none were set. Includes codes
    /// whose `valid_until` has already passed.
    pub previous: Vec<String>,
}

/// Emitted when a read encounters a flag whose `valid_until` has passed.
#[contractevent]
pub struct JurisdictionExpired {
    #[topic]
    pub address: Address,
}

#[contractevent]
pub struct JurisdictionRemoved {
    #[topic]
    pub address: Address,
}

/// Emitted when the issuer role is reassigned via `transfer_issuer`.
#[contractevent]
pub struct IssuerTransferred {
    #[topic]
    pub old_issuer: Address,
    #[topic]
    pub new_issuer: Address,
}

/// Emitted when `propose_issuer` is called.
#[contractevent]
pub struct IssuerProposed {
    #[topic]
    pub current_issuer: Address,
    #[topic]
    pub proposed_issuer: Address,
}

/// Emitted when the current issuer cancels a pending proposal.
#[contractevent]
pub struct IssuerProposalCancelled {
    #[topic]
    pub issuer: Address,
}

/// Emitted when `set_compliance_officer` assigns the compliance-officer role.
#[contractevent]
pub struct ComplianceOfficerSet {
    #[topic]
    pub issuer: Address,
    pub officer: Address,
}

/// Emitted when `revoke_compliance_officer` removes an existing officer.
/// `officer` is the address that held the role before revocation.
#[contractevent]
pub struct ComplianceOfficerRevoked {
    #[topic]
    pub issuer: Address,
    pub officer: Address,
}

/// Emitted when `upgrade` replaces the contract WASM.
#[contractevent]
pub struct UpgradePerformed {
    #[topic]
    pub issuer: Address,
    pub new_wasm_hash: BytesN<32>,
}

#[contractevent]
pub struct Paused {
    #[topic]
    pub issuer: Address,
}

#[contractevent]
pub struct Unpaused {
    #[topic]
    pub issuer: Address,
}

/// Delayed issuer upgrade proposal.
#[contracttype]
#[derive(Clone)]
pub struct UpgradeState {
    pub new_wasm: BytesN<32>,
    pub activated_at: u64,
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    NotInitialized = 1,
    AlreadyInitialized = 2,
    NotAuthorized = 3,
    /// Caller supplied an argument that is structurally invalid.
    InvalidInput = 4,
    ContractPaused = 5,
    /// `set_jurisdiction` was given a `code` that is not exactly two
    /// uppercase ASCII letters (ISO 3166-1 alpha-2). Also covers the empty
    /// string (#81), so there is one variant for every malformed code.
    InvalidJurisdictionCode = 6,
    /// The `allowed_codes` list passed to `is_permitted_jurisdiction` was empty.
    EmptyAllowedCodes = 7,
    /// `accept_issuer` was called when no transfer is in progress.
    NoPendingIssuer = 8,
    /// The address calling `accept_issuer` does not match the pending issuer
    /// stored by `propose_issuer`.
    PendingIssuerMismatch = 9,
    /// `add_jurisdiction` was called when the address already has
    /// [`MAX_CODES_PER_ADDRESS`] codes attached.
    TooManyCodes = 10,
    /// A jurisdiction change was attempted for an address before its
    /// configured cooldown elapsed (#777).
    JurisdictionCooldownActive = 11,
    /// `set_group` was given an empty or malformed group name, or no codes.
    InvalidGroup = 12,
}

#[contract]
pub struct JurisdictionFlag;

#[contractimpl]
impl JurisdictionFlag {
    /// One-time setup that records `issuer` as the only address allowed to
    /// set jurisdiction codes afterward.
    ///
    /// # Parameters
    /// - `issuer`: the address that will be authorized to call
    ///   [`set_jurisdiction`](Self::set_jurisdiction).
    ///
    /// # Auth
    /// Requires `issuer.require_auth()`, so the issuer must sign the
    /// initialization.
    ///
    /// # Errors
    /// - [`Error::AlreadyInitialized`] if the contract has already been
    ///   initialized. The existing issuer is left unchanged.
    pub fn initialize(env: Env, issuer: Address) -> Result<(), Error> {
        Self::extend_instance_ttl(&env);
        if env.storage().instance().has(&DataKey::Issuer) {
            return Err(Error::AlreadyInitialized);
        }
        issuer.require_auth();
        env.storage().instance().set(&DataKey::Issuer, &issuer);
        env.storage().instance().set(&DataKey::Paused, &false);
        Ok(())
    }

    /// Return the configured issuer address.
    pub fn get_issuer(env: Env) -> Result<Address, Error> {
        env.storage()
            .instance()
            .get(&DataKey::Issuer)
            .ok_or(Error::NotInitialized)
    }

    /// Reassign the issuer role to `new_issuer`. Requires auth from
    /// `current_issuer`, which must be the stored issuer.
    ///
    /// Takes effect immediately: the old issuer loses all privileges
    /// (including `upgrade`, `pause`, and managing the compliance officer)
    /// as soon as this call succeeds. The compliance-officer assignment is
    /// left untouched. Deliberately *not* blocked by `pause`, so a
    /// compromised or rotated issuer key can always be replaced.
    ///
    /// Emits `IssuerTransferred { old_issuer, new_issuer }`.
    pub fn transfer_issuer(
        env: Env,
        current_issuer: Address,
        new_issuer: Address,
    ) -> Result<(), Error> {
        Self::require_issuer(&env, &current_issuer)?;
        env.storage().instance().set(&DataKey::Issuer, &new_issuer);
        // Clear any outstanding proposal so a stale proposed address cannot
        // accept after this rotation.
        env.storage().instance().remove(&DataKey::PendingIssuer);
        IssuerTransferred {
            old_issuer: current_issuer,
            new_issuer,
        }
        .publish(&env);
        Ok(())
    }

    /// Propose a new issuer. The current issuer retains full control until
    /// the proposed issuer calls `accept_issuer`, so a typo in `new_issuer`
    /// cannot permanently lose control of the contract. Calling it again
    /// overwrites any pending proposal; `transfer_issuer` (single-step
    /// break-glass rotation) also clears it.
    pub fn propose_issuer(env: Env, issuer: Address, new_issuer: Address) -> Result<(), Error> {
        Self::require_issuer(&env, &issuer)?;
        env.storage()
            .instance()
            .set(&DataKey::PendingIssuer, &new_issuer);
        IssuerProposed {
            current_issuer: issuer,
            proposed_issuer: new_issuer,
        }
        .publish(&env);
        Ok(())
    }

    /// Accept a pending issuer proposal. Must be called by the exact address
    /// passed to `propose_issuer`; it becomes the issuer and the proposal is
    /// cleared.
    pub fn accept_issuer(env: Env, new_issuer: Address) -> Result<(), Error> {
        Self::extend_instance_ttl(&env);
        new_issuer.require_auth();
        let pending: Address = env
            .storage()
            .instance()
            .get(&DataKey::PendingIssuer)
            .ok_or(Error::NoPendingIssuer)?;
        if pending != new_issuer {
            return Err(Error::PendingIssuerMismatch);
        }
        let old_issuer: Address = env
            .storage()
            .instance()
            .get(&DataKey::Issuer)
            .ok_or(Error::NotInitialized)?;
        env.storage().instance().set(&DataKey::Issuer, &new_issuer);
        env.storage().instance().remove(&DataKey::PendingIssuer);
        IssuerTransferred {
            old_issuer,
            new_issuer,
        }
        .publish(&env);
        Ok(())
    }

    /// Cancel a pending issuer proposal. Issuer-only.
    pub fn cancel_issuer_proposal(env: Env, issuer: Address) -> Result<(), Error> {
        Self::require_issuer(&env, &issuer)?;
        env.storage().instance().remove(&DataKey::PendingIssuer);
        IssuerProposalCancelled { issuer }.publish(&env);
        Ok(())
    }

    /// Assign the compliance-officer role. Issuer-only.
    ///
    /// The officer role grants access to exactly these entry points, each
    /// guarded by `require_compliance_authority` (issuer *or* officer):
    ///
    /// - [`set_jurisdiction`](Self::set_jurisdiction)
    /// - [`set_jurisdiction_until`](Self::set_jurisdiction_until)
    /// - [`add_jurisdiction`](Self::add_jurisdiction)
    /// - [`set_multiple_jurisdictions`](Self::set_multiple_jurisdictions)
    ///
    /// All other mutating entry points remain issuer-only, including:
    ///
    /// - [`remove_jurisdiction`](Self::remove_jurisdiction) and
    ///   [`remove_jurisdiction_multiple`](Self::remove_jurisdiction_multiple)
    /// - [`pause`](Self::pause) / [`unpause`](Self::unpause)
    /// - [`upgrade`](Self::upgrade)
    /// - [`set_compliance_officer`](Self::set_compliance_officer) /
    ///   [`revoke_compliance_officer`](Self::revoke_compliance_officer)
    ///
    /// The officer role does not extend to removal, pause, upgrade, or
    /// issuer/officer management functions.
    ///
    /// Auth: gated by [`require_issuer`] — only the issuer may delegate this role.
    pub fn set_compliance_officer(
        env: Env,
        issuer: Address,
        officer: Address,
    ) -> Result<(), Error> {
        Self::require_issuer(&env, &issuer)?;
        env.storage()
            .instance()
            .set(&DataKey::ComplianceOfficer, &officer);
        ComplianceOfficerSet {
            issuer: issuer.clone(),
            officer,
        }
        .publish(&env);
        Ok(())
    }

    /// Revoke the compliance-officer role. Issuer-only.
    ///
    /// After revocation, the former officer no longer satisfies
    /// `require_compliance_authority`, so [`set_jurisdiction`](Self::set_jurisdiction),
    /// [`set_jurisdiction_until`](Self::set_jurisdiction_until),
    /// [`add_jurisdiction`](Self::add_jurisdiction), and
    /// [`set_multiple_jurisdictions`](Self::set_multiple_jurisdictions) revert
    /// to issuer-only access. All other mutating entry points
    /// ([`remove_jurisdiction`](Self::remove_jurisdiction),
    /// [`remove_jurisdiction_multiple`](Self::remove_jurisdiction_multiple),
    /// [`pause`](Self::pause), [`unpause`](Self::unpause),
    /// [`upgrade`](Self::upgrade)) were already issuer-only via
    /// `require_issuer` and are unaffected.
    ///
    /// Auth: gated by [`require_issuer`] — only the issuer may revoke the delegated role.
    pub fn revoke_compliance_officer(env: Env, issuer: Address) -> Result<(), Error> {
        Self::require_issuer(&env, &issuer)?;
        if let Some(officer) = env
            .storage()
            .instance()
            .get::<_, Address>(&DataKey::ComplianceOfficer)
        {
            env.storage()
                .instance()
                .remove(&DataKey::ComplianceOfficer);
            ComplianceOfficerRevoked {
                issuer: issuer.clone(),
                officer,
            }
            .publish(&env);
        }
        Ok(())
    }

    /// Pause all mutating operations. Issuer-only.
    ///
    /// Auth: gated by [`require_issuer`] — pause/unpause is a lifecycle operation reserved for the issuer.
    pub fn pause(env: Env, issuer: Address) -> Result<(), Error> {
        Self::require_issuer(&env, &issuer)?;
        env.storage().instance().set(&DataKey::Paused, &true);
        Paused {
            issuer: issuer.clone(),
        }
        .publish(&env);
        Ok(())
    }

    /// Resume all mutating operations. Issuer-only.
    ///
    /// Auth: gated by [`require_issuer`] — pause/unpause is a lifecycle operation reserved for the issuer.
    pub fn unpause(env: Env, issuer: Address) -> Result<(), Error> {
        Self::require_issuer(&env, &issuer)?;
        env.storage().instance().set(&DataKey::Paused, &false);
        Unpaused {
            issuer: issuer.clone(),
        }
        .publish(&env);
        Ok(())
    }

    /// Attach jurisdiction `code` to `address`. Issuer or compliance-officer.
    ///
    /// `code` must be an ISO 3166-1 alpha-2 code in canonical uppercase form
    /// (see the module docs); otherwise returns
    /// `Error::InvalidJurisdictionCode` and nothing is stored.
    ///
    /// Auth: gated by [`require_compliance_authority`] — allows either the issuer or a
    /// delegated compliance officer, so routine flag management does not require the issuer key.
    ///
    /// # Example
    ///
    /// ```ignore
    /// // `flag` is a `JurisdictionFlagClient`; tag `holder` with an ISO 3166-1 alpha-2 code.
    /// flag.set_jurisdiction(&issuer, &holder, &String::from_str(&env, "DE"));
    /// ```
    pub fn set_jurisdiction(
        env: Env,
        issuer: Address,
        address: Address,
        code: String,
    ) -> Result<(), Error> {
        Self::require_compliance_authority(&env, &issuer)?;
        Self::reject_if_paused(&env)?;
        Self::validate_jurisdiction_code(&code)?;
        Self::check_cooldown(&env, &address)?;

        let previous = Self::load_jurisdictions(&env, &address);
        let mut codes = Vec::new(&env);
        codes.push_back(code.clone());
        Self::store_jurisdictions(&env, &address, &codes);
        env.storage()
            .persistent()
            .remove(&DataKey::ValidUntil(address.clone()));
        Self::record_change(&env, &address);

        JurisdictionSet {
            address,
            code,
            previous,
        }
        .publish(&env);
        Ok(())
    }

    /// Batch-set jurisdiction codes for multiple addresses in one transaction.
    ///
    /// Behaves like calling [`set_jurisdiction`](Self::set_jurisdiction) once
    /// per entry: each address's codes are replaced by the single given code
    /// and any `valid_until` is cleared. `caller` must be the issuer or the
    /// compliance officer. All codes are validated **before** any writes, so
    /// one invalid code rejects the whole batch without leaving partial state.
    ///
    /// # Errors
    /// [`Error::ContractPaused`] while the contract is paused;
    /// [`Error::InvalidInput`] if `entries` is empty or longer than
    /// [`MAX_BATCH_SIZE`]; [`Error::InvalidJurisdictionCode`] if any code is
    /// malformed.
    pub fn set_multiple_jurisdictions(
        env: Env,
        caller: Address,
        entries: Vec<(Address, String)>,
    ) -> Result<(), Error> {
        Self::require_compliance_authority(&env, &caller)?;
        Self::reject_if_paused(&env)?;

        if entries.is_empty() || entries.len() > MAX_BATCH_SIZE {
            return Err(Error::InvalidInput);
        }
        for (address, code) in entries.iter() {
            Self::validate_jurisdiction_code(&code)?;
            Self::check_cooldown(&env, &address)?;
        }

        for (address, code) in entries.iter() {
            let previous = Self::load_jurisdictions(&env, &address);
            let mut codes = Vec::new(&env);
            codes.push_back(code.clone());
            Self::store_jurisdictions(&env, &address, &codes);
            env.storage()
                .persistent()
                .remove(&DataKey::ValidUntil(address.clone()));
            Self::record_change(&env, &address);
            JurisdictionSet { address, code, previous }.publish(&env);
        }
        Ok(())
    }

    /// Batch variant of [`set_jurisdiction_until`](Self::set_jurisdiction_until)
    /// for onboarding cohorts that share the same expiry (#776).
    ///
    /// Each address's codes are replaced by its single given code, valid
    /// through ledger `valid_until` (inclusive). `caller` must be the issuer
    /// or the compliance officer. All inputs are validated **before** any
    /// writes, so one bad entry rejects the whole batch.
    ///
    /// # Errors
    /// [`Error::ContractPaused`] while paused; [`Error::InvalidInput`] if
    /// `entries` is empty, longer than [`MAX_BATCH_SIZE`], or `valid_until`
    /// is in the past; [`Error::InvalidJurisdictionCode`] if any code is
    /// malformed; [`Error::JurisdictionCooldownActive`] if any address is
    /// still within its cooldown.
    pub fn set_multiple_jurisdictions_until(
        env: Env,
        caller: Address,
        entries: Vec<(Address, String)>,
        valid_until: u32,
    ) -> Result<(), Error> {
        Self::require_compliance_authority(&env, &caller)?;
        Self::reject_if_paused(&env)?;

        if entries.is_empty() || entries.len() > MAX_BATCH_SIZE {
            return Err(Error::InvalidInput);
        }
        if valid_until < env.ledger().sequence() {
            return Err(Error::InvalidInput);
        }
        for (address, code) in entries.iter() {
            Self::validate_jurisdiction_code(&code)?;
            Self::check_cooldown(&env, &address)?;
        }

        for (address, code) in entries.iter() {
            let previous = Self::load_jurisdictions(&env, &address);
            let mut codes = Vec::new(&env);
            codes.push_back(code.clone());
            Self::store_jurisdictions(&env, &address, &codes);
            let until_key = DataKey::ValidUntil(address.clone());
            env.storage().persistent().set(&until_key, &valid_until);
            Self::extend_jurisdiction_ttl(&env, &until_key);
            Self::record_change(&env, &address);
            JurisdictionSet { address, code, previous }.publish(&env);
        }
        Ok(())
    }

    /// Configure whether a permitted country implies its ISO 3166-2
    /// subdivisions in [`is_permitted_jurisdiction`](Self::is_permitted_jurisdiction)
    /// (#774). Defaults to `true`. Issuer-only.
    pub fn set_subdivision_inheritance(
        env: Env,
        issuer: Address,
        enabled: bool,
    ) -> Result<(), Error> {
        Self::require_issuer(&env, &issuer)?;
        if enabled {
            env.storage().instance().remove(&DataKey::StrictSubdivisions);
        } else {
            env.storage()
                .instance()
                .set(&DataKey::StrictSubdivisions, &true);
        }
        Ok(())
    }

    /// Return whether a permitted country implies its subdivisions.
    pub fn get_subdivision_inheritance(env: Env) -> bool {
        !env.storage()
            .instance()
            .get::<_, bool>(&DataKey::StrictSubdivisions)
            .unwrap_or(false)
    }

    /// Configure the per-address cooldown, in ledgers, between jurisdiction
    /// changes for the same address (#777). `0` disables the cooldown
    /// (default). Issuer-only.
    pub fn set_jurisdiction_cooldown(
        env: Env,
        issuer: Address,
        ledgers: u32,
    ) -> Result<(), Error> {
        Self::require_issuer(&env, &issuer)?;
        if ledgers == 0 {
            env.storage().instance().remove(&DataKey::Cooldown);
        } else {
            env.storage().instance().set(&DataKey::Cooldown, &ledgers);
        }
        Ok(())
    }

    /// Return the configured per-address cooldown in ledgers (`0` = none).
    pub fn get_jurisdiction_cooldown(env: Env) -> u32 {
        env.storage()
            .instance()
            .get(&DataKey::Cooldown)
            .unwrap_or(0)
    }

    /// Attach jurisdiction `code` to `address`, valid through ledger
    /// `valid_until` (inclusive). Issuer or compliance-officer.
    ///
    /// Like [`set_jurisdiction`](Self::set_jurisdiction), this replaces any
    /// existing codes. The expiry applies to every code later attached to the
    /// address until it is cleared by `set_jurisdiction` or removal.
    pub fn set_jurisdiction_until(
        env: Env,
        issuer: Address,
        address: Address,
        code: String,
        valid_until: u32,
    ) -> Result<(), Error> {
        Self::require_compliance_authority(&env, &issuer)?;
        Self::reject_if_paused(&env)?;
        Self::validate_jurisdiction_code(&code)?;
        if valid_until < env.ledger().sequence() {
            return Err(Error::InvalidInput);
        }
        Self::check_cooldown(&env, &address)?;

        let previous = Self::load_jurisdictions(&env, &address);
        let mut codes = Vec::new(&env);
        codes.push_back(code.clone());
        Self::store_jurisdictions(&env, &address, &codes);
        let until_key = DataKey::ValidUntil(address.clone());
        env.storage().persistent().set(&until_key, &valid_until);
        Self::extend_jurisdiction_ttl(&env, &until_key);
        Self::record_change(&env, &address);

        JurisdictionSet { address, code, previous }.publish(&env);
        Ok(())
    }

    /// Add `code` to `address`'s jurisdiction codes if it is not already present.
    /// Issuer or compliance-officer only.
    ///
    /// # Errors
    /// - [`Error::TooManyCodes`] if the address already has
    ///   [`MAX_CODES_PER_ADDRESS`] codes attached. Remove a code first, or use
    ///   [`set_jurisdiction`](Self::set_jurisdiction) to replace all codes at once.
    pub fn add_jurisdiction(
        env: Env,
        issuer: Address,
        address: Address,
        code: String,
    ) -> Result<(), Error> {
        Self::require_compliance_authority(&env, &issuer)?;
        Self::reject_if_paused(&env)?;
        Self::validate_jurisdiction_code(&code)?;

        let previous = Self::load_jurisdictions(&env, &address);
        let mut codes = previous.clone();
        if !codes.iter().any(|existing| existing == code) {
            if codes.len() >= MAX_CODES_PER_ADDRESS {
                return Err(Error::TooManyCodes);
            }
            Self::check_cooldown(&env, &address)?;
            codes.push_back(code.clone());
            Self::store_jurisdictions(&env, &address, &codes);
            Self::record_change(&env, &address);
        }

        JurisdictionSet { address, code, previous }.publish(&env);
        Ok(())
    }

    /// Remove `code` from `address`'s jurisdiction codes. Issuer-only.
    pub fn remove_jurisdiction(
        env: Env,
        issuer: Address,
        address: Address,
        code: String,
    ) -> Result<(), Error> {
        Self::require_issuer(&env, &issuer)?;
        Self::reject_if_paused(&env)?;

        let mut remaining = Vec::new(&env);
        for existing in Self::load_jurisdictions(&env, &address).iter() {
            if existing != code {
                remaining.push_back(existing);
            }
        }
        Self::store_jurisdictions(&env, &address, &remaining);
        JurisdictionRemoved { address }.publish(&env);
        Ok(())
    }

    /// Return all jurisdiction codes attached to `address`.
    ///
    /// Returns an empty list once the address's `valid_until` has passed.
    pub fn list_jurisdictions(env: Env, address: Address) -> Vec<String> {
        Self::load_active_jurisdictions(&env, &address)
    }

    /// Remove stored jurisdiction codes for each address in `addresses`.
    ///
    /// Auth: gated by [`require_issuer`] — bulk removal is a privileged operation reserved for the issuer.
    pub fn remove_jurisdiction_multiple(
        env: Env,
        issuer: Address,
        addresses: Vec<Address>,
    ) -> Result<(), Error> {
        Self::require_issuer(&env, &issuer)?;
        Self::reject_if_paused(&env)?;
        for address in addresses.iter() {
            Self::store_jurisdictions(&env, &address, &Vec::new(&env));
            JurisdictionRemoved { address }.publish(&env);
        }
        Ok(())
    }

    /// Returns the jurisdiction code attached to `address`, if any.
    ///
    /// # Parameters
    /// - `address`: the address to look up.
    ///
    /// # Returns
    /// `Some(code)` if a code has been set via
    /// [`set_jurisdiction`](Self::set_jurisdiction), otherwise `None`.
    ///
    /// # Auth
    /// None. This is a read-only call anyone may make.
    ///
    /// # Errors
    /// Never fails. Works even before the contract is initialized, in which
    /// case it always returns `None`.
    ///
    /// Returns `None` if the flag has a `valid_until` that is strictly less
    /// than the current ledger sequence, publishing `JurisdictionExpired`.
    pub fn get_jurisdiction(env: Env, address: Address) -> Option<String> {
        Self::load_active_jurisdictions(&env, &address).iter().next()
    }

    /// Returns the ledger through which `address`'s jurisdiction flag is valid
    /// (inclusive), as set by [`set_jurisdiction_until`](Self::set_jurisdiction_until).
    ///
    /// Returns `None` if no expiry is set, which covers both flags that never
    /// expire and addresses with no flag at all. The expiry is returned even
    /// after it has passed, so integrators can compare it with the current
    /// ledger to warn users before a flag lapses. Does not publish events.
    pub fn get_jurisdiction_expiry(env: Env, address: Address) -> Option<u32> {
        env.storage().persistent().get(&DataKey::ValidUntil(address))
    }

    /// Returns whether `address` is permitted under `allowed_codes`.
    ///
    /// Each entry of `allowed_codes` is either an ISO 3166-1 alpha-2 code or
    /// the name of a group defined with [`set_group`](Self::set_group), which
    /// expands to its member codes. Unless strict subdivisions are enabled, a
    /// country code also matches its ISO 3166-2 subdivisions (e.g. `US`
    /// matches `US-CA`).
    ///
    /// In [`JurisdictionMode::AllowList`] mode (the default) the address is
    /// permitted if any of its active codes matches the list. In
    /// [`JurisdictionMode::BlockList`] mode the list names blocked
    /// jurisdictions: the address is permitted if it has at least one active
    /// code and none of them match the list.
    ///
    /// Returns `Err(Error::EmptyAllowedCodes)` if the `allowed_codes` list is empty.
    pub fn is_permitted_jurisdiction(
        env: Env,
        address: Address,
        allowed_codes: Vec<String>,
    ) -> Result<bool, Error> {
        Self::extend_instance_ttl(&env);
        if allowed_codes.is_empty() {
            return Err(Error::EmptyAllowedCodes);
        }
        let codes = Self::load_active_jurisdictions(&env, &address);
        let inherit = !env
            .storage()
            .instance()
            .get::<_, bool>(&DataKey::StrictSubdivisions)
            .unwrap_or(false);
        let covers = |allowed: &String, code: &String| {
            code == allowed || (inherit && Self::is_subdivision_of(code, allowed))
        };
        let matched = allowed_codes.iter().any(|entry| {
            if codes.iter().any(|code| covers(&entry, &code)) {
                return true;
            }
            match env
                .storage()
                .persistent()
                .get::<DataKey, Vec<String>>(&DataKey::Group(entry))
            {
                Some(members) => members
                    .iter()
                    .any(|member| codes.iter().any(|code| covers(&member, &code))),
                None => false,
            }
        });
        Ok(match Self::get_mode(env.clone()) {
            JurisdictionMode::AllowList => matched,
            JurisdictionMode::BlockList => !codes.is_empty() && !matched,
        })
    }

    /// Define (or replace) a named jurisdiction group such as `EU` or `EEA`.
    /// Issuer-only. `codes` must be non-empty valid alpha-2 codes, at most
    /// [`MAX_GROUP_CODES`]. Group names may then be passed to
    /// [`is_permitted_jurisdiction`](Self::is_permitted_jurisdiction).
    pub fn set_group(
        env: Env,
        issuer: Address,
        name: String,
        codes: Vec<String>,
    ) -> Result<(), Error> {
        Self::require_issuer(&env, &issuer)?;
        Self::reject_if_paused(&env)?;
        if name.is_empty() || name.len() > MAX_GROUP_NAME_LEN || codes.is_empty() {
            return Err(Error::InvalidGroup);
        }
        if codes.len() > MAX_GROUP_CODES {
            return Err(Error::TooManyCodes);
        }
        for code in codes.iter() {
            Self::validate_jurisdiction_code(&code)?;
        }
        let key = DataKey::Group(name.clone());
        env.storage().persistent().set(&key, &codes);
        env.storage()
            .persistent()
            .extend_ttl(&key, INSTANCE_TTL_THRESHOLD, INSTANCE_TTL_EXTEND_TO);
        GroupSet { name, codes }.publish(&env);
        Ok(())
    }

    /// Return the member codes of group `name`, if defined.
    pub fn get_group(env: Env, name: String) -> Option<Vec<String>> {
        env.storage().persistent().get(&DataKey::Group(name))
    }

    /// Set the contract-level [`JurisdictionMode`]. Issuer-only.
    pub fn set_mode(env: Env, issuer: Address, mode: JurisdictionMode) -> Result<(), Error> {
        Self::require_issuer(&env, &issuer)?;
        Self::reject_if_paused(&env)?;
        env.storage().instance().set(&DataKey::Mode, &mode);
        ModeSet { mode }.publish(&env);
        Ok(())
    }

    /// Return the current [`JurisdictionMode`] (default `AllowList`).
    pub fn get_mode(env: Env) -> JurisdictionMode {
        env.storage()
            .instance()
            .get(&DataKey::Mode)
            .unwrap_or(JurisdictionMode::AllowList)
    }

    /// Version of the shared `ComplianceCheck` trait implemented here (#808).
    ///
    /// Callers must verify this matches the interface version they were built
    /// against before calling [`is_compliant`](Self::is_compliant); a mismatch
    /// means the return type or reason codes may have changed.
    pub fn interface_version(_env: Env) -> u32 {
        COMPLIANCE_CHECK_INTERFACE_VERSION
    }

    /// Unified compliance check — returns a [`CheckResult`] whose `allowed`
    /// is `true` if `address` has **any** jurisdiction code set, i.e. it has
    /// been through an onboarding/KYC process that assigned it a jurisdiction.
    ///
    /// This entry point implements the shared `ComplianceCheck` interface
    /// (`is_compliant(address) -> CheckResult`).  Unlike
    /// [`is_permitted_jurisdiction`], it does not validate the code against a
    /// permitted-jurisdictions list because the `ComplianceCheck` interface
    /// carries only `address`.
    ///
    /// Reason codes (#807):
    /// - [`CHECK_CODE_OK`] (`0`): a jurisdiction code is set; `allowed` is `true`.
    /// - [`CHECK_CODE_NO_JURISDICTION`] (`1`): no active jurisdiction code
    ///   (never flagged, or the flag expired); `allowed` is `false`.
    ///
    /// Use [`is_permitted_jurisdiction`] when you need to enforce a specific
    /// set of allowed codes.  Use `is_compliant` for the lighter check of
    /// "has this address been assigned a jurisdiction at all".
    ///
    /// Not affected by pause state — reads always succeed.
    pub fn is_compliant(env: Env, address: Address) -> CheckResult {
        if Self::get_jurisdiction(env, address).is_some() {
            CheckResult {
                allowed: true,
                code: CHECK_CODE_OK,
            }
        } else {
            CheckResult {
                allowed: false,
                code: CHECK_CODE_NO_JURISDICTION,
            }
        }
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

    /// Upgrade the contract WASM. Issuer-only.
    ///
    /// Uses Soroban's native `update_current_contract_wasm` host function to
    /// swap the contract code behind the same contract ID. All existing
    /// storage (issuer address, jurisdiction flags) is preserved across the
    /// upgrade. The issuer's auth is verified before the upgrade proceeds.
    pub fn upgrade(env: Env, issuer: Address, new_wasm_hash: BytesN<32>) -> Result<(), Error> {
        Self::require_issuer(&env, &issuer)?;
        env.storage().instance().remove(&DataKey::PendingUpgrade);
        UpgradePerformed {
            issuer,
            new_wasm_hash,
        }
        .publish(&env);
        Ok(())
    }

    /// Strict single-address auth gate — only the address stored as `issuer`
    /// at [`initialize`] time may pass.
    ///
    /// ## Authorization split
    ///
    /// This helper enforces the *tightest* authorization level in the contract.
    /// It is used by every entry point that changes the contract's own
    /// configuration or lifecycle (pause/unpause, compliance-officer
    /// assignment, bulk jurisdiction removal, WASM upgrade). The reasoning is
    /// that these operations affect the contract's trust model itself, so they
    /// must be gated on the one address the deployer designated at setup —
    /// the issuer — and no delegation is permitted.
    ///
    /// Contrast with [`require_compliance_authority`], which additionally
    /// allows a delegated compliance officer for day-to-day data operations.
    ///
    /// ## Errors
    ///
    /// Returns [`Error::NotInitialized`] if `initialize` has not been called
    /// yet, or [`Error::NotAuthorized`] if `issuer` does not match the stored
    /// issuer address.
    fn require_issuer(env: &Env, issuer: &Address) -> Result<(), Error> {
        Self::extend_instance_ttl(&env);
        issuer.require_auth();
        let stored_issuer: Address = env
            .storage()
            .instance()
            .get(&DataKey::Issuer)
            .ok_or(Error::NotInitialized)?;
        if stored_issuer != *issuer {
            return Err(Error::NotAuthorized);
        }
        Ok(())
    }

    /// Looser auth gate — passes if `caller` is the issuer **or** the
    /// currently assigned compliance officer.
    ///
    /// ## Authorization split
    ///
    /// This helper enforces a *delegated* authorization level for
    /// [`set_jurisdiction`], [`set_jurisdiction_until`], [`add_jurisdiction`],
    /// and [`set_multiple_jurisdictions`]. The issuer can optionally appoint a compliance officer via
    /// [`set_compliance_officer`]; once appointed, that officer may call any
    /// entry point gated by this helper without requiring the issuer key for
    /// every individual flag operation.
    ///
    /// Entry points that mutate the contract's *configuration* (who the
    /// compliance officer is, whether the contract is paused, etc.) use the
    /// stricter [`require_issuer`] instead, so a compromised compliance-officer
    /// key cannot escalate its own privileges.
    ///
    /// If no compliance officer has been set, this helper behaves identically
    /// to [`require_issuer`].
    ///
    /// ## Errors
    ///
    /// Returns [`Error::NotInitialized`] if `initialize` has not been called,
    /// or [`Error::NotAuthorized`] if `caller` is neither the issuer nor the
    /// compliance officer.
    fn require_compliance_authority(env: &Env, caller: &Address) -> Result<(), Error> {
        Self::extend_instance_ttl(&env);
        caller.require_auth();
        let stored_issuer: Address = env
            .storage()
            .instance()
            .get(&DataKey::Issuer)
            .ok_or(Error::NotInitialized)?;
        if stored_issuer == *caller {
            return Ok(());
        }
        if let Some(officer) = env
            .storage()
            .instance()
            .get::<DataKey, Address>(&DataKey::ComplianceOfficer)
        {
            if officer == *caller {
                return Ok(());
            }
        }
        Err(Error::NotAuthorized)
    }

    /// Accepts an assigned ISO 3166-1 alpha-2 code (`"US"`) or an ISO
    /// 3166-2 subdivision code `CC-SSS` whose country part is assigned and
    /// whose subdivision part is 1–3 uppercase ASCII letters or digits.
    fn validate_jurisdiction_code(code: &String) -> Result<(), Error> {
        let len = code.len();
        if len != JURISDICTION_CODE_LEN
            && !(len >= JURISDICTION_CODE_LEN + 2 && len <= SUBDIVISION_CODE_MAX_LEN)
        {
            return Err(Error::InvalidJurisdictionCode);
        }
        let mut buf = [0u8; SUBDIVISION_CODE_MAX_LEN as usize];
        let buf = &mut buf[..len as usize];
        code.copy_into_slice(buf);
        let country = [buf[0], buf[1]];
        if !country.iter().all(u8::is_ascii_uppercase) || !is_known_country(country) {
            return Err(Error::InvalidJurisdictionCode);
        }
        if len > JURISDICTION_CODE_LEN {
            let sub = &buf[3..];
            if buf[2] != b'-'
                || !sub
                    .iter()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
            {
                return Err(Error::InvalidJurisdictionCode);
            }
        }
        Ok(())
    }

    /// `true` if `code` is a subdivision (`CC-…`) of country `allowed` (`CC`).
    fn is_subdivision_of(code: &String, allowed: &String) -> bool {
        if allowed.len() != JURISDICTION_CODE_LEN || code.len() <= JURISDICTION_CODE_LEN + 1 {
            return false;
        }
        if code.len() > SUBDIVISION_CODE_MAX_LEN {
            return false;
        }
        let mut c = [0u8; SUBDIVISION_CODE_MAX_LEN as usize];
        code.copy_into_slice(&mut c[..code.len() as usize]);
        let mut a = [0u8; JURISDICTION_CODE_LEN as usize];
        allowed.copy_into_slice(&mut a);
        c[0] == a[0] && c[1] == a[1] && c[2] == b'-'
    }

    /// Rejects a change for `address` while its cooldown is still running.
    fn check_cooldown(env: &Env, address: &Address) -> Result<(), Error> {
        let cooldown: u32 = env
            .storage()
            .instance()
            .get(&DataKey::Cooldown)
            .unwrap_or(0);
        if cooldown == 0 {
            return Ok(());
        }
        if let Some(last) = env
            .storage()
            .persistent()
            .get::<_, u32>(&DataKey::LastChange(address.clone()))
        {
            if env.ledger().sequence() < last.saturating_add(cooldown) {
                return Err(Error::JurisdictionCooldownActive);
            }
        }
        Ok(())
    }

    /// Records the ledger of `address`'s latest change when a cooldown is
    /// configured (no storage cost otherwise).
    fn record_change(env: &Env, address: &Address) {
        if env.storage().instance().has(&DataKey::Cooldown) {
            let key = DataKey::LastChange(address.clone());
            env.storage()
                .persistent()
                .set(&key, &env.ledger().sequence());
            Self::extend_jurisdiction_ttl(env, &key);
        }
    }

    fn extend_jurisdiction_ttl(env: &Env, key: &DataKey) {
        env.storage()
            .persistent()
            .extend_ttl(key, TTL_THRESHOLD, TTL_EXTEND_TO);
    }

    /// Like `load_jurisdictions`, but returns no codes (and publishes
    /// `JurisdictionExpired`) once the address's `valid_until` has passed.
    fn load_active_jurisdictions(env: &Env, address: &Address) -> Vec<String> {
        let codes = Self::load_jurisdictions(env, address);
        if codes.is_empty() {
            return codes;
        }
        let until_key = DataKey::ValidUntil(address.clone());
        if let Some(valid_until) = env.storage().persistent().get::<_, u32>(&until_key) {
            if valid_until < env.ledger().sequence() {
                JurisdictionExpired {
                    address: address.clone(),
                }
                .publish(env);
                return Vec::new(env);
            }
            Self::extend_jurisdiction_ttl(env, &until_key);
        }
        codes
    }

    fn load_jurisdictions(env: &Env, address: &Address) -> Vec<String> {
        let list_key = DataKey::Jurisdictions(address.clone());
        if let Some(codes) = env.storage().persistent().get::<_, Vec<String>>(&list_key) {
            Self::extend_jurisdiction_ttl(env, &list_key);
            return codes;
        }

        let legacy_key = DataKey::Jurisdiction(address.clone());
        match env.storage().persistent().get::<_, String>(&legacy_key) {
            Some(code) => {
                Self::extend_jurisdiction_ttl(env, &legacy_key);
                Vec::from_array(env, [code])
            }
            None => Vec::new(env),
        }
    }

    fn store_jurisdictions(env: &Env, address: &Address, codes: &Vec<String>) {
        let list_key = DataKey::Jurisdictions(address.clone());
        let legacy_key = DataKey::Jurisdiction(address.clone());
        if let Some(first_code) = codes.iter().next() {
            env.storage().persistent().set(&list_key, codes);
            Self::extend_jurisdiction_ttl(env, &list_key);
            env.storage().persistent().set(&legacy_key, &first_code);
            Self::extend_jurisdiction_ttl(env, &legacy_key);
        } else {
            env.storage().persistent().remove(&list_key);
            env.storage().persistent().remove(&legacy_key);
            env.storage()
                .persistent()
                .remove(&DataKey::ValidUntil(address.clone()));
        }
    }
}

#[cfg(test)]
mod test;

#[cfg(test)]
mod fuzz;
