# Galeon Privacy Pools Specification

> Compliant Privacy Mixing for Private Payments

> ⚠️ **DEPRECATED (Jan 2026):** This spec is no longer actively maintained and may be out of sync with the implementation.
>
> **For current implementation details, refer to:**
>
> - Contract code: `packages/contracts/contracts/privacy-pool/`
> - Operations guide: `packages/contracts/OPERATIONS.md`
> - Trust model: See "Current Trust Assumptions" section below (kept current)
>
> **Known outdated sections:**
>
> - Code snippets use old function names (e.g., `isValidPortAddress` → `canDeposit`)
> - "Fog wallets" references - we now use direct Pool withdrawals
> - Some freeze/ragequit details may not match implementation

## Overview

Privacy Pools is a mixing protocol that allows Galeon users to break the link between receiving and sending payments, while maintaining full compliance capability.

**Key Innovation**: Port-only deposits mean all funds are "pre-vetted" - they came from covenant signers paying each other.

**The Galeon Covenant**: Users sign a compliance agreement to join, creating a self-policing community of good actors.

**Core Principle**: Privacy from the public, not from law enforcement.

---

## Compliance Architecture Summary

### The Galeon Trust Model (Explicit)

**What Galeon CAN See/Do:**

- All Port payments (viewing key escrow → scan announcements)
- Link commitments to depositors (`commitmentDepositor` mapping)
- Block future deposits from flagged addresses
- Exclude commitments from valid set (freeze withdrawals)
- IP logs, covenant signatures, fog wallet metadata (if stored)

**What Galeon CANNOT See/Do:**

- Spend user funds (no spending keys)
- Link withdrawal to deposit (ZK proof hides which commitment)
- See withdrawal destination (stealth address, no viewing key)
- Modify Merkle tree after deposit (immutable)

| Layer    | Privacy From Public      | Privacy From Galeon                                   | Freeze Capability             |
| -------- | ------------------------ | ----------------------------------------------------- | ----------------------------- |
| **Port** | ✅ Yes (stealth address) | ❌ No (viewing key escrow)                            | ❌ No (user has spending key) |
| **Pool** | ✅ Yes (ZK proofs)       | ✅ Partial (can't trace withdrawal, CAN link deposit) | ✅ Yes (exclusion set)        |

> **User Understanding**: Users should know Galeon is NOT a trustless protocol. It's "privacy from public + compliance capability" not "privacy from everyone."

**Current Trust Assumptions:**

1. **Viewing Key Custody**: Port viewing keys are stored server-side (encrypted with APP_KEY). The server can scan announcements and link inbound payments to ports. Users trust Galeon to handle this data responsibly.

2. **ASP Control**: The Association Set Provider (ASP) is Galeon-operated. Galeon decides which commitments are in the "valid set" for withdrawals. Excluded users cannot withdraw normally, but can always ragequit (original depositor exit, no ASP approval needed).

3. **Contract Upgradeability**: Contracts may be upgradeable. Users trust Galeon not to introduce malicious upgrades.

These assumptions are intentional for the compliance model. Users seeking trustless privacy should use other protocols.

---

### Port-Only Deposit Enforcement (Concrete Mechanism)

**Problem**: Stealth addresses don't inherently prove they came from a Port payment.

**Solution**: GaleonRegistry tracks all stealth addresses that received payments:

```solidity
// In GaleonRegistry.payNative():
isPortStealthAddress[stealthAddress] = true;
verifiedBalance[stealthAddress] += netAmount;

// In GaleonPrivacyPool.deposit():
require(
    galeonRegistry.isValidPortAddress(msg.sender),
    "Depositor must be a Port stealth address"
);
require(
    msg.value <= galeonRegistry.getVerifiedBalance(msg.sender),
    "Amount exceeds verified balance"
);

// Deduct from verified balance to prevent double-deposit
galeonRegistry.consumeVerifiedBalance(msg.sender, msg.value);
```

**Flow:**

```
1. Payer → GaleonRegistry.payNative() → stealth address receives 1 MNT
   └── Registry records: isPortStealthAddress[stealth] = true
   └── Registry records: verifiedBalance[stealth] = 1 MNT

2. Stealth owner → GaleonPrivacyPool.deposit(commitment)
   └── Pool checks: galeonRegistry.isValidPortAddress(msg.sender) ✅
   └── Pool checks: msg.value <= verifiedBalance[msg.sender] ✅
   └── Registry decrements: verifiedBalance[stealth] -= 1 MNT
   └── Pool records: commitmentDepositor[commitment] = msg.sender

3. Attacker sends dirty MNT directly to stealth address
   └── verifiedBalance stays at 0 (not from GaleonRegistry)
   └── Stealth can't deposit dirty funds (exceeds verifiedBalance)
```

**Edge Case - Direct Sends:**
If someone sends MNT directly to a stealth address (not via GaleonRegistry):

- `verifiedBalance` is NOT incremented
- User can spend those funds normally (collect, send)
- User CANNOT deposit them to Privacy Pool
- This is the intended behavior (only "clean" funds in pool)

---

### ASP/Exclusion System (Following 0xbow Pattern)

**0xbow Model**: Uses separate Association Sets (valid depositors vs excluded depositors), NOT Merkle tree pruning.

```
┌─────────────────────────────────────────────────────────────┐
│                    0xbow ASP PATTERN                         │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   DEPOSIT MERKLE TREE (immutable after deposit)             │
│   ┌───────────────────────────────────────────────┐         │
│   │  All commitments ever deposited               │         │
│   │  Root changes only on new deposits            │         │
│   │  NEVER modified/pruned after deposit          │         │
│   └───────────────────────────────────────────────┘         │
│                                                              │
│   ASSOCIATION SET (ASP-controlled)                          │
│   ┌───────────────────────────────────────────────┐         │
│   │  Valid Set: Commitments allowed to withdraw   │         │
│   │  └── Updated by ASP (add/remove)              │         │
│   │                                               │         │
│   │  Exclusion Set: Commitments blocked           │         │
│   │  └── Bad actors, sanctioned addresses         │         │
│   └───────────────────────────────────────────────┘         │
│                                                              │
│   WITHDRAWAL PROOF must prove:                              │
│   1. Commitment exists in Merkle tree (membership)          │
│   2. Commitment is in Valid Set (association)               │
│   3. Nullifier is fresh (not double-spent)                  │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

**Galeon Implementation:**

```solidity
// ASP-controlled exclusion (does NOT modify Merkle tree)
mapping(bytes32 => bool) public excludedCommitments;
bytes32 public aspRoot; // Root of valid association set

event CommitmentExcluded(bytes32 indexed commitment, string reason);
event CommitmentReincluded(bytes32 indexed commitment);

/// @notice ASP excludes a commitment (freeze)
function excludeCommitment(bytes32 commitment, string calldata reason) external onlyASP {
    require(commitments[commitment], "Commitment not in pool");
    require(!excludedCommitments[commitment], "Already excluded");

    excludedCommitments[commitment] = true;
    exclusions[commitment] = Exclusion({
        excluded: true,
        excludedAt: block.timestamp,
        amount: DENOMINATION,
        depositor: commitmentDepositor[commitment]
    });

    // Update ASP root (recalculate valid set)
    _updateASPRoot();

    emit CommitmentExcluded(commitment, reason);
}

/// @notice Withdrawal must prove membership in BOTH trees
function withdraw(
    bytes calldata merkleProof,    // Proves: commitment in deposit tree
    bytes calldata aspProof,       // Proves: commitment in valid set
    bytes32 root,
    bytes32 aspRoot_,
    bytes32 nullifierHash,
    address payable recipient,
    ...
) external {
    // Verify merkle membership (deposit tree - immutable)
    require(isKnownRoot(root), "Invalid merkle root");

    // Verify ASP membership (valid set - mutable)
    require(aspRoot_ == aspRoot, "Invalid ASP root");
    require(!excludedCommitments[commitment], "Commitment excluded");

    // ... rest of withdrawal logic
}
```

**Why This Doesn't Break Proofs:**

- Merkle tree is NEVER modified → old proofs still valid for membership
- ASP root is separate → exclusion only affects ASP proof
- Innocent users regenerate ASP proof with new root (simple)
- Excluded users can't generate valid ASP proof (blocked)

---

### Stealth-Only Withdrawals + Relayer Considerations

**Problem Without Relayer:**

```
1. User wants to withdraw to fresh stealth address
2. Fresh address has 0 MNT (can't pay gas)
3. User must fund it from somewhere → linkage leak!

Options without relayer:
a) Fund from exchange → links exchange account to stealth
b) Fund from existing wallet → links wallets
c) Use Pool withdrawal gas from another address → still needs funding
```

**Solution: Relayer Support (Future)**

```solidity
function withdraw(
    bytes calldata proof,
    bytes32 root,
    bytes32 nullifierHash,
    address payable recipient,
    address relayer,           // Relayer pays gas
    uint256 relayerFee         // Relayer compensation (from withdrawal)
) external {
    // ... verification ...

    uint256 protocolFee = (DENOMINATION * withdrawalFeeBps) / 10000;
    uint256 netAmount = DENOMINATION - protocolFee - relayerFee;

    // Pay relayer (covers their gas cost + profit)
    if (relayer != address(0) && relayerFee > 0) {
        payable(relayer).transfer(relayerFee);
    }

    // Pay protocol fee
    if (protocolFee > 0) {
        payable(treasury).transfer(protocolFee);
    }

    // Pay recipient
    payable(recipient).transfer(netAmount);
}
```

**Hackathon Scope:**

- ❌ No relayer (users must self-fund stealth addresses)
- ⚠️ Document linkage risk in UI: "Funding this address may reduce privacy"
- ✅ Contract supports relayer parameter (ready for future)

**Future Relayer Network:**

- Decentralized relayers compete on fees
- User generates proof locally, sends to relayer
- Relayer submits tx, receives fee from withdrawal
- No linkage between user's funding source and stealth address

---

### Revenue/Freeze Interaction (Detailed)

**Scenario: User deposits 1 MNT, gets excluded, then appeals**

```
Timeline:
Day 0:   User deposits 1 MNT, commitment C created
Day 5:   ASP excludes commitment C (flagged as bad actor)
Day 10:  User appeals exclusion
Day 35:  Appeal period ends (30 days from exclusion)
Day 36:  Treasury can claim frozen funds

Fee handling:
- No withdrawal fee charged (user never withdrew)
- No donation collected (user never withdrew)
- Full 1 MNT goes to treasury (minus gas)
```

**Contract Implementation:**

```solidity
struct Exclusion {
    bool excluded;
    uint256 excludedAt;
    uint256 amount;          // Frozen amount (DENOMINATION)
    address depositor;       // Original depositor
    bool appealed;           // Appeal filed
    bool appealResolved;     // Appeal decision made
    bool appealGranted;      // If true, funds returned to depositor
}

uint256 public constant APPEAL_PERIOD = 30 days;

/// @notice Claim frozen funds after appeal period (treasury only)
function claimFrozenFunds(bytes32 commitment) external {
    Exclusion storage exc = exclusions[commitment];

    require(exc.excluded, "Not excluded");
    require(!exc.appealGranted, "Appeal was granted");
    require(
        block.timestamp >= exc.excludedAt + APPEAL_PERIOD,
        "Appeal period not ended"
    );
    require(!frozenFundsClaimed[commitment], "Already claimed");

    frozenFundsClaimed[commitment] = true;

    // NO withdrawal fee on frozen funds (punitive, not service)
    // Full amount to treasury
    payable(treasury).transfer(exc.amount);

    emit FrozenFundsClaimed(commitment, exc.amount);
}

/// @notice Grant appeal - return funds to depositor
function grantAppeal(bytes32 commitment) external onlyASP {
    Exclusion storage exc = exclusions[commitment];

    require(exc.excluded, "Not excluded");
    require(exc.appealed, "No appeal filed");
    require(!exc.appealResolved, "Already resolved");

    exc.appealResolved = true;
    exc.appealGranted = true;
    exc.excluded = false;

    // Re-add to valid set
    _updateASPRoot();

    // User can now withdraw normally (with fees)
    emit AppealGranted(commitment);
}
```

**Fee Rules:**
| Scenario | Protocol Fee | Donation | Recipient |
|----------|--------------|----------|-----------|
| Normal withdrawal | 0.3% | Optional | User |
| Frozen → Treasury claim | 0% | N/A | Treasury |
| Frozen → Appeal granted | 0.3% (on eventual withdraw) | Optional | User |

---

## Revenue Configuration

### Revenue Streams

| Stream                   | Type     | Hackathon | Production | Configurable | Description                          |
| ------------------------ | -------- | --------- | ---------- | ------------ | ------------------------------------ |
| **Pool Withdrawal Fee**  | Fee      | **0%**    | 0.3%       | ✅ Yes       | % of withdrawn amount to treasury    |
| **Port Creation Fee**    | Fee      | **0 MNT** | 0.01 MNT   | ✅ Yes       | One-time fee for creating a Port     |
| **Payment Fee**          | Fee      | **0%**    | 0%         | ✅ Yes       | % of payments through GaleonRegistry |
| **Donation (Withdraw)**  | Optional | 0%        | 0%         | User choice  | User can tip treasury on withdraw    |
| **Donation (Payment)**   | Optional | 0%        | 0%         | User choice  | User can tip treasury on payment     |
| **Frozen Fund Recovery** | Treasury | N/A       | N/A        | N/A          | Unclaimed frozen funds after appeal  |

### Fee Parameters (Configurable by Owner/Governance)

```solidity
// GaleonRegistry fee parameters
uint256 public portCreationFee;      // Hackathon: 0, Production: 0.01 MNT
uint256 public paymentFeeBps;        // Hackathon: 0, Production: 0

// GaleonPrivacyPool fee parameters
uint256 public withdrawalFeeBps;     // Hackathon: 0, Production: 30 (0.3%)
uint256 public constant MAX_FEE_BPS = 500; // 5% max (protect users)

// Treasury
address public treasury;             // Receives all fees and donations
```

> **Hackathon Strategy**: All fees set to 0 for maximum adoption. Fee collection code is ready but disabled - flip switch for production.

### Revenue Collection Points

```
1. PORT CREATION (GaleonRegistry)
   └── User pays portCreationFee → Treasury

2. PAYMENT (GaleonRegistry.payNative)
   └── Fee: paymentFeeBps of amount → Treasury
   └── Optional: User adds donation → Treasury

3. POOL WITHDRAWAL (GaleonPrivacyPool.withdraw)
   └── Fee: withdrawalFeeBps of amount → Treasury
   └── Optional: User adds donation → Treasury

4. FROZEN FUND RECOVERY (GaleonPrivacyPool.claimFrozenFunds)
   └── Full amount after appeal period → Treasury
```

### Launch Strategy (Hackathon → Production)

| Phase             | Port Fee     | Payment Fee | Withdraw Fee | Notes               |
| ----------------- | ------------ | ----------- | ------------ | ------------------- |
| **Hackathon**     | 0 MNT        | 0%          | 0%           | Maximum adoption    |
| **Beta**          | 0 MNT        | 0%          | 0.1%         | Test fee collection |
| **Production v1** | 0.01 MNT     | 0%          | 0.3%         | Sustainable revenue |
| **Future**        | Configurable | 0.1%?       | 0.3%         | DAO governance      |

### Donation Integration (Optional Tips)

Users can optionally donate to Galeon treasury at key moments:

```solidity
// In GaleonPrivacyPool.withdraw
function withdraw(
    bytes calldata proof,
    ...
    uint256 donationBps  // 0 = no donation, user can choose 1-1000 (0.01%-10%)
) external {
    uint256 amount = DENOMINATION;
    uint256 fee = (amount * withdrawalFeeBps) / 10000;
    uint256 donation = (amount * donationBps) / 10000;
    uint256 netAmount = amount - fee - donation;

    // Transfer
    treasury.transfer(fee + donation);
    recipient.transfer(netAmount);

    emit Withdrawn(..., fee, donation);
}
```

### Revenue Projections (Example)

| Scenario  | Monthly Volume | Withdraw Fee (0.3%) | Monthly Revenue |
| --------- | -------------- | ------------------- | --------------- |
| Hackathon | 100 MNT        | $0                  | $0              |
| Early     | 10,000 MNT     | $30                 | ~$30            |
| Growth    | 100,000 MNT    | $300                | ~$300           |
| Scale     | 1M MNT         | $3,000              | ~$3,000         |

_Note: Donations are upside - even 1% average donation rate doubles revenue_

---

## Implementation: Fork 0xbow (v1)

### Decision: Fork 0xbow Instead of Building v0

**Why 0xbow:**

- Vitalik Buterin deposited 1 ETH and invested in pre-seed
- Ethereum Foundation integrating into Kohaku wallet
- $6M+ volume, 1,500+ users since March 2025 mainnet launch
- $3.5M seed (Coinbase Ventures)
- Production-tested Groth16 circuits + ASP system
- BN254 curve is native on Mantle (EIP-196/197)

**What We Keep from 0xbow:**

- Groth16 ZK proofs (Poseidon hash, BN254 curve)
- Merkle tree of deposits (depth 20)
- Nullifier-based double-spend prevention
- Full ASP system

**What We Add (Galeon-specific):**

- Port-only deposits (covenant compliance)
- Stealth-only withdrawals (EIP-5564 integration)
- Galeon Covenant integration

| Component         | v1 Implementation (0xbow Fork)  | Future Upgrades                           |
| ----------------- | ------------------------------- | ----------------------------------------- |
| **Pool Deposits** | Port addresses only             | Add external deposits with chain analysis |
| **ASP**           | 0xbow ASP system + ban list     | DAO governance + chain analysis APIs      |
| **Shipwreck**     | Owner-only reports              | Community reporting with reputation       |
| **ZK Proofs**     | Groth16 (0xbow circuits)        | Multi-denomination pools                  |
| **Withdrawals**   | To registered stealth addresses | Add relayer for gas-free withdrawals      |

### v1 Architecture (0xbow Fork)

```
┌─────────────────────────────────────────────────────────────────────┐
│                      GALEON v1 - 0xbow FORK + PORT-ONLY              │
├─────────────────────────────────────────────────────────────────────┤
│                                                                       │
│   FLOW: Receive → Pool (ZK) → Withdraw → Pay                         │
│                                                                       │
│   ┌──────────────────┐                                               │
│   │  PORT RECEIVES   │  ← Someone pays your payment link             │
│   │  PAYMENT         │  ← Covenant signer, verified clean            │
│   └────────┬─────────┘                                               │
│            │                                                          │
│            ▼                                                          │
│   ┌──────────────────┐                                               │
│   │  DEPOSIT TO      │  ← commitment = Poseidon(nullifier, secret)   │
│   │  PRIVACY POOL    │  ← Added to Merkle tree (depth 20)            │
│   └────────┬─────────┘                                               │
│            │                                                          │
│            │  Pool grows, anonymity set increases                    │
│            ▼                                                          │
│   ┌──────────────────┐                                               │
│   │  WITHDRAW WITH   │  ← ZK proof: "I know a secret in the tree"    │
│   │  ZK PROOF        │  ← Nullifier prevents double-spend            │
│   └────────┬─────────┘  ← ASP proves deposit is "good"               │
│            │                                                          │
│            ▼                                                          │
│   ┌──────────────────┐                                               │
│   │  FOG WALLET      │  ← Registered stealth address                 │
│   │  RECEIVES FUNDS  │  ← No on-chain link to deposit                │
│   └────────┬─────────┘                                               │
│            │                                                          │
│            ▼                                                          │
│   ┌──────────────────┐                                               │
│   │  PAY FROM        │  ← Private payment to any address             │
│   │  FOG WALLET      │  ← Source is cryptographically hidden         │
│   └──────────────────┘                                               │
│                                                                       │
│   WHY 0xbow FORK:                                                     │
│   • Vitalik-backed, production-tested ($6M+ volume)                  │
│   • Groth16 ZK proofs - true cryptographic unlinkability             │
│   • BN254 curve native on Mantle (EIP-196/197)                       │
│   • Full ASP system for compliance                                   │
│                                                                       │
│   GALEON ADDITIONS:                                                   │
│   • Port-only deposits (covenant signers)                            │
│   • Stealth-only withdrawals (EIP-5564)                              │
│   • Covenant integration for compliance                              │
│                                                                       │
└─────────────────────────────────────────────────────────────────────┘
```

### Future Upgrades (v2+)

- External deposits with Chainalysis/TRM Labs integration
- Community Shipwreck reporting with reputation system
- DAO-controlled ASP governance
- Multi-denomination pools
- Relayer network for gas-free withdrawals

---

## The Galeon Covenant

### Core Concept

> "Private payments for good actors."

When users join Galeon, they sign the **Galeon Covenant** - a cryptographic agreement that:

1. Attests they're not a bad actor
2. Commits to reporting if they discover bad actors
3. Accepts that Galeon may exclude violators

**This is the "catch"** - you can't just use the privacy pool anonymously. You must sign in.

### Why This Works

```
┌─────────────────────────────────────────────────────────────────┐
│                    THE GALEON FLYWHEEL                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   ┌──────────────┐                                              │
│   │ User wants   │                                              │
│   │ privacy      │                                              │
│   └──────┬───────┘                                              │
│          │                                                       │
│          ▼                                                       │
│   ┌──────────────┐     ┌──────────────┐     ┌──────────────┐   │
│   │ Signs        │────▶│ Creates      │────▶│ Joins        │   │
│   │ Covenant     │     │ Port         │     │ Privacy Pool │   │
│   └──────────────┘     └──────────────┘     └──────────────┘   │
│          │                                          │            │
│          │                                          ▼            │
│          │                                  ┌──────────────┐    │
│          │                                  │ Anonymity    │    │
│          │                                  │ set grows    │    │
│          │                                  └──────┬───────┘    │
│          │                                         │            │
│          ▼                                         ▼            │
│   ┌──────────────────────────────────────────────────────┐     │
│   │            BETTER PRIVACY FOR EVERYONE                │     │
│   └──────────────────────────────────────────────────────┘     │
│                                                                  │
│   BAD ACTORS:                                                    │
│   • Must sign covenant (creates liability)                      │
│   • Will eventually be reported by counterparties               │
│   • Get excluded from pool (funds stuck)                        │
│   • Pool survives (unlike Tornado Cash)                         │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Covenant Data Structure

```typescript
// EIP-712 Typed Data for Covenant Signature
const COVENANT_TYPES = {
  GaleonCovenant: [
    { name: 'signer', type: 'address' },
    { name: 'stealthMetaAddress', type: 'string' },
    { name: 'attestations', type: 'Attestations' },
    { name: 'version', type: 'uint256' },
    { name: 'timestamp', type: 'uint256' },
  ],
  Attestations: [
    { name: 'notSanctioned', type: 'bool' },
    { name: 'fundsLegitimate', type: 'bool' },
    { name: 'willReport', type: 'bool' },
    { name: 'acceptsTerms', type: 'bool' },
  ],
}

interface GaleonCovenant {
  // Identity
  signer: `0x${string}` // Main wallet address
  stealthMetaAddress: string // Their st:mnt:... address

  // Attestations (all must be true to sign)
  attestations: {
    notSanctioned: true // "I'm not on OFAC/UN/EU sanctions lists"
    fundsLegitimate: true // "My funds are not from illegal activities"
    willReport: true // "I'll report if I discover my counterparty is bad"
    acceptsTerms: true // "I accept Galeon's terms and exclusion rights"
  }

  // Metadata
  version: 1 // Covenant version (for upgrades)
  timestamp: number // When signed (Unix ms)

  // The signature
  signature: `0x${string}` // EIP-712 typed signature
}
```

### Covenant Storage

| Location     | Data                      | Purpose                              |
| ------------ | ------------------------- | ------------------------------------ |
| On-chain     | `covenantHash`            | Proof user signed (can't deny later) |
| Backend      | Full covenant + signature | Verification, legal compliance       |
| LocalStorage | Signature only            | Quick re-verification                |

### Covenant On-Chain Storage (Integrated in GaleonRegistry)

> **Design Decision:** Covenant storage is integrated into `GaleonRegistry`, not a separate contract.
> This reduces deployment complexity, gas costs, and simplifies the architecture.

Covenant functionality is added directly to GaleonRegistry (see full contract below).

---

## Viral Growth Mechanics

### The Payment Link Flywheel

```
┌─────────────────────────────────────────────────────────────────┐
│                    GALEON VIRAL LOOP                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   FREELANCER                                                     │
│   "I want to get paid without revealing my wallet"               │
│         │                                                        │
│         ▼                                                        │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │  1. Signs Covenant                                       │   │
│   │  2. Creates Port (payment link)                          │   │
│   │  3. Shares: "Pay me at galeon.finance/pay/alice"            │   │
│   └─────────────────────────────────────────────────────────┘   │
│         │                                                        │
│         │ Shares link with clients                               │
│         ▼                                                        │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │  CLIENT WANTS TO PAY                                     │   │
│   │  └── "I want to pay privately too!"                     │   │
│   │  └── Signs Covenant                                      │   │
│   │  └── Creates their own Port                              │   │
│   │  └── Joins Privacy Pool                                  │   │
│   └─────────────────────────────────────────────────────────┘   │
│         │                                                        │
│         │ Client shares with their network                       │
│         ▼                                                        │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │  NETWORK EFFECT                                          │   │
│   │  └── More users = better anonymity set                  │   │
│   │  └── Better privacy attracts more users                 │   │
│   │  └── Cycle repeats                                       │   │
│   └─────────────────────────────────────────────────────────┘   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### User Acquisition Channels

| User Type           | Motivation                     | Entry Point            |
| ------------------- | ------------------------------ | ---------------------- |
| Freelancers         | Private payments from clients  | Payment link           |
| Privacy enthusiasts | Maximum transaction privacy    | Privacy Pool           |
| DAOs                | Anonymous contributor payments | Port creation          |
| Businesses          | Compliant payroll privacy      | Covenant = audit trail |
| Crypto natives      | Hide wallet balances           | Fog wallets            |

### The "Catch" That Makes It Work

> **You must sign the Covenant to use Galeon.**

This means:

1. **No anonymous bad actors** - Everyone has signed identity on record
2. **Self-policing community** - Users report suspicious activity
3. **Regulatory defensibility** - "We require compliance attestation"
4. **Pool survival** - Unlike Tornado, we can exclude bad actors

---

## Shipwreck Reporting System

### What is Shipwreck?

"Shipwreck" is Galeon's compliance and reporting system. The metaphor:

- **Ships** = Transactions in the privacy pool
- **Wrecks** = Bad actors discovered and excluded
- **Lighthouse** = The reporting system that protects the fleet

### Report Types

```typescript
type ShipwreckReportType =
  | 'suspected_stolen' // Funds may be from theft/hack
  | 'counterparty_admitted' // Other party revealed illicit source
  | 'sanctions_match' // Address matches sanctions list
  | 'chain_analysis' // On-chain patterns suggest illicit
  | 'legal_request' // Law enforcement request
  | 'other' // Custom reason
```

### Report Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                    SHIPWRECK REPORT FLOW                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  STEP 1: USER SUBMITS REPORT                                     │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │  Report Suspicious Activity                                 ││
│  │                                                             ││
│  │  Transaction: 0x1234...5678                                 ││
│  │  Type: ○ Suspected stolen funds                            ││
│  │        ● Counterparty revealed illicit source              ││
│  │        ○ Sanctions match                                    ││
│  │                                                             ││
│  │  Evidence:                                                  ││
│  │  ┌─────────────────────────────────────────────────────┐   ││
│  │  │ They mentioned in our chat that this was from...   │   ││
│  │  └─────────────────────────────────────────────────────┘   ││
│  │                                                             ││
│  │  [Submit Report]                                            ││
│  └─────────────────────────────────────────────────────────────┘│
│                                                                  │
│  STEP 2: GALEON REVIEWS                                          │
│  • Cross-reference with sanctions databases                      │
│  • Check chain analysis (Chainalysis, TRM Labs APIs)            │
│  • Review evidence provided                                      │
│  • Multiple reports = higher priority                            │
│                                                                  │
│  STEP 3: DECISION                                                │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │  IF CONFIRMED BAD ACTOR:                                    ││
│  │  • Exclude all their deposits from ASP tree                ││
│  │  • Update on-chain ASP root                                 ││
│  │  • Their funds are stuck (can't withdraw with valid proof) ││
│  │  • Reporter gets reputation boost                           ││
│  │                                                             ││
│  │  IF FALSE REPORT:                                           ││
│  │  • No action taken                                          ││
│  │  • If malicious, reporter loses reputation                  ││
│  └─────────────────────────────────────────────────────────────┘│
│                                                                  │
│  STEP 4: TRANSPARENCY                                            │
│  • Publish exclusion reason (without doxxing reporter)          │
│  • Community can verify bad actor was real                      │
│  • Pool continues operating (not sanctioned like Tornado)       │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Report Data Structure

```typescript
interface ShipwreckReport {
  id: string

  // Reporter (kept confidential)
  reporterAddress: `0x${string}`
  reporterCovenantHash: `0x${string}`

  // Subject
  suspectedAddress: `0x${string}`
  relatedTxHash?: `0x${string}`
  relatedDepositCommitment?: `0x${string}`

  // Details
  reportType: ShipwreckReportType
  evidence: string

  // Metadata
  submittedAt: number
  status: 'pending' | 'investigating' | 'confirmed' | 'rejected'

  // Resolution (if any)
  resolution?: {
    decision: 'exclude' | 'dismiss'
    reason: string
    decidedAt: number
    aspRootUpdated?: `0x${string}` // New ASP root after exclusion
  }
}
```

### ASP Exclusion Process

```typescript
class GaleonASP {
  private excludedAddresses: Set<Address> = new Set()
  private associationTree: MerkleTree

  /**
   * Called when a Shipwreck report is confirmed
   */
  async excludeBadActor(report: ShipwreckReport): Promise<void> {
    const { suspectedAddress } = report

    // 1. Add to exclusion list
    this.excludedAddresses.add(suspectedAddress)

    // 2. Find all their deposits in the pool
    const theirDeposits = await this.findDepositsFrom(suspectedAddress)

    // 3. Remove from association tree
    for (const deposit of theirDeposits) {
      this.associationTree.remove(deposit.commitment)
    }

    // 4. Update on-chain root
    const newRoot = this.associationTree.root
    await this.contract.updateASPRoot(newRoot)

    // 5. Log for transparency
    await this.publishExclusion({
      address: suspectedAddress,
      reason: report.reportType,
      excludedAt: Date.now(),
      depositsAffected: theirDeposits.length,
      newAspRoot: newRoot,
    })

    console.log(
      `[Shipwreck] Excluded ${suspectedAddress}, ${theirDeposits.length} deposits affected`
    )
  }

  /**
   * Check if new deposit should be included
   */
  async isDepositGood(depositAddress: Address): Promise<boolean> {
    // Already excluded?
    if (this.excludedAddresses.has(depositAddress)) {
      return false
    }

    // On sanctions list?
    if (await this.checkSanctions(depositAddress)) {
      return false
    }

    // From a Port (covenant signer)?
    const isFromPort = await this.isPortAddress(depositAddress)
    if (isFromPort) {
      // Extra trust - they signed the covenant
      return true
    }

    // External deposit - run chain analysis
    const riskScore = await this.chainAnalysis(depositAddress)
    return riskScore < RISK_THRESHOLD
  }
}
```

---

## Onboarding Flow

### First-Time User Experience

```
┌─────────────────────────────────────────────────────────────────┐
│                    GALEON ONBOARDING                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  STEP 1: LANDING                                                 │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                                                             ││
│  │              🛡️ GALEON                                      ││
│  │         Private payments for good actors                    ││
│  │                                                             ││
│  │  • Receive payments without revealing your wallet          ││
│  │  • Send with maximum privacy                                ││
│  │  • Compliant by design                                      ││
│  │                                                             ││
│  │              [Connect Wallet]                               ││
│  │                                                             ││
│  └─────────────────────────────────────────────────────────────┘│
│                                                                  │
│  STEP 2: COVENANT SIGNING                                        │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                                                             ││
│  │              The Galeon Covenant                            ││
│  │                                                             ││
│  │  To use Galeon's privacy features, please confirm:         ││
│  │                                                             ││
│  │  ☑️ I am not on any government sanctions list              ││
│  │     (OFAC, UN, EU, or similar)                             ││
│  │                                                             ││
│  │  ☑️ My funds are not from illegal activities               ││
│  │     (theft, fraud, terrorism, etc.)                        ││
│  │                                                             ││
│  │  ☑️ I will report suspicious activity                      ││
│  │     (if I discover my counterparty is a bad actor)        ││
│  │                                                             ││
│  │  ☑️ I accept that Galeon may exclude bad actors            ││
│  │     (violators lose access to privacy pool)               ││
│  │                                                             ││
│  │  By signing, you join our community of good actors.        ││
│  │  The more people join, the better privacy for everyone.   ││
│  │                                                             ││
│  │              [Sign with Wallet]                             ││
│  │                                                             ││
│  └─────────────────────────────────────────────────────────────┘│
│                                                                  │
│  STEP 3: STEALTH KEYS                                            │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                                                             ││
│  │              Generate Your Stealth Keys                     ││
│  │                                                             ││
│  │  Sign one more message to generate your privacy keys.      ││
│  │  These never leave your browser.                           ││
│  │                                                             ││
│  │              [Generate Keys]                                ││
│  │                                                             ││
│  └─────────────────────────────────────────────────────────────┘│
│                                                                  │
│  STEP 4: READY                                                   │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                                                             ││
│  │              ✅ You're in!                                  ││
│  │                                                             ││
│  │  Your stealth address:                                      ││
│  │  st:mnt:0x1234...5678                                      ││
│  │                                                             ││
│  │  What's next?                                               ││
│  │                                                             ││
│  │  ┌──────────────────┐  ┌──────────────────┐                ││
│  │  │  📥 Receive      │  │  📤 Send         │                ││
│  │  │  ──────────────  │  │  ──────────────  │                ││
│  │  │  Create payment  │  │  Create fog      │                ││
│  │  │  links           │  │  wallets         │                ││
│  │  └──────────────────┘  └──────────────────┘                ││
│  │                                                             ││
│  └─────────────────────────────────────────────────────────────┘│
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Compliance & Law Enforcement Cooperation

### The Doxxing Capability

> **Privacy is not anonymity. Galeon provides privacy from the public, not from law enforcement.**

When required by law or for confirmed bad actors, Galeon can reveal user identity through multiple mechanisms:

### What We Retain (Compliance Data)

| Data Type                      | Stored Where        | Links To                  |
| ------------------------------ | ------------------- | ------------------------- |
| **Covenant Signature**         | On-chain + Backend  | Signer EOA address        |
| **Stealth Meta Address**       | Covenant registry   | EOA that generated it     |
| **Port Registrations**         | Backend database    | EOA + meta address        |
| **Fog Wallet Derivation Path** | Backend (encrypted) | Master signature hash     |
| **Pool Deposits**              | On-chain            | Source address (Port/EOA) |
| **Pool Withdrawals**           | On-chain            | Recipient stealth address |
| **Shipwreck Reports**          | Backend             | Reporter + subject        |
| **IP Addresses**               | Backend logs        | All actions (optional)    |

### Identity Resolution Chain

```
┌─────────────────────────────────────────────────────────────────────┐
│                    IDENTITY RESOLUTION CHAIN                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  Given: A suspicious Fog wallet stealth address                       │
│                                                                       │
│  STEP 1: Stealth Address → Meta Address                               │
│  ┌─────────────────────────────────────────────────────────────────┐ │
│  │  Fog wallet was created with ephemeral key from masterSignature  │ │
│  │  + stealth meta address. We can trace back via:                  │ │
│  │    • Pool withdrawal records (if from pool)                       │ │
│  │    • Port transfer records (if from Port)                         │ │
│  │    • Fog wallet metadata (stored encrypted)                       │ │
│  └─────────────────────────────────────────────────────────────────┘ │
│                                                                       │
│  STEP 2: Meta Address → Covenant                                      │
│  ┌─────────────────────────────────────────────────────────────────┐ │
│  │  Every meta address is registered in the Covenant:                │ │
│  │    covenant.stealthMetaAddress = "st:mnt:..."                     │ │
│  │    covenant.signer = "0xABC..." ← EOA REVEALED                    │ │
│  └─────────────────────────────────────────────────────────────────┘ │
│                                                                       │
│  STEP 3: EOA → Real Identity                                          │
│  ┌─────────────────────────────────────────────────────────────────┐ │
│  │  EOA can be traced through:                                       │ │
│  │    • CEX KYC records (if funded from exchange)                    │ │
│  │    • ENS / social recovery / linked accounts                      │ │
│  │    • On-chain transaction history                                 │ │
│  │    • Subpoena to wallet providers                                 │ │
│  └─────────────────────────────────────────────────────────────────┘ │
│                                                                       │
│  RESULT: Full identity disclosure possible when legally required.     │
│                                                                       │
└─────────────────────────────────────────────────────────────────────┘
```

### Law Enforcement Request Process

```typescript
interface LawEnforcementRequest {
  // Request metadata
  id: string
  requestedAt: number
  requestingAgency: string // "FBI", "SEC", "Europol", etc.
  jurisdiction: string // "US", "EU", etc.
  legalBasis: string // Court order reference, subpoena ID

  // Target information
  targetType: 'address' | 'transaction' | 'meta_address' | 'port_name'
  targetValue: string // The address/tx/name being investigated

  // What they want
  requestedData: (
    | 'identity' // Covenant signer address
    | 'transaction_history' // All pool deposits/withdrawals
    | 'linked_addresses' // All stealth addresses from same meta
    | 'port_registry' // Port registration details
    | 'ip_logs' // IP addresses (if retained)
    | 'full_disclosure' // Everything
  )[]

  // Response
  status: 'pending' | 'fulfilled' | 'rejected' | 'partial'
  responseData?: ComplianceResponse
  fulfilledAt?: number
  rejectionReason?: string // "Invalid jurisdiction", "Insufficient legal basis"
}

interface ComplianceResponse {
  // Covenant data
  covenantSigner?: `0x${string}`
  covenantSignedAt?: number
  covenantHash?: `0x${string}`

  // Meta address data
  stealthMetaAddress?: string
  derivedAddresses?: `0x${string}`[] // All known stealth addresses

  // Transaction data
  poolDeposits?: PoolDeposit[]
  poolWithdrawals?: PoolWithdrawal[]
  portTransfers?: PortTransfer[]
}
```

### Compliance Levels

| Level         | Privacy                        | When Applied                      |
| ------------- | ------------------------------ | --------------------------------- |
| **Normal**    | Full privacy from public       | Default for all users             |
| **Flagged**   | Monitored, no action yet       | Shipwreck report pending          |
| **Frozen**    | Can't withdraw from pool       | Confirmed bad actor               |
| **Disclosed** | Identity revealed to requester | Valid law enforcement request     |
| **Public**    | Identity published             | Court order for public disclosure |

### What Makes This Different From Nocturne

| Capability                 | Nocturne     | Galeon                            |
| -------------------------- | ------------ | --------------------------------- |
| **Covenant with EOA link** | ❌ No        | ✅ Yes - signed with main wallet  |
| **Meta address registry**  | ❌ No        | ✅ Yes - covenant stores it       |
| **Transaction tracing**    | ❌ No        | ✅ Yes - Port/Pool records        |
| **Shipwreck reporting**    | ❌ No        | ✅ Yes - community enforcement    |
| **Law enforcement API**    | ❌ No        | ✅ Yes - formal process           |
| **Selective disclosure**   | ❌ No        | ✅ Yes - reveal one user, not all |
| **Pool survival**          | ❌ Shut down | ✅ Exclude bad actor, continue    |

### Technical Disclosure Implementation

```solidity
// contracts/GaleonComplianceRegistry.sol
contract GaleonComplianceRegistry {
    // Only Galeon multisig can disclose (after legal verification)
    address public complianceOfficer;

    // Frozen addresses (can't withdraw from pool)
    mapping(address => bool) public isFrozen;
    mapping(address => string) public freezeReason;

    // Disclosed addresses (public record)
    mapping(address => bool) public isDisclosed;
    mapping(address => string) public disclosureReference; // Court order ID

    event AddressFrozen(address indexed target, string reason, uint256 timestamp);
    event AddressDisclosed(address indexed target, string legalReference, uint256 timestamp);
    event FreezeLifted(address indexed target, uint256 timestamp);

    /**
     * @notice Freeze an address (prevent pool withdrawals)
     * @param target The address to freeze
     * @param reason Why (e.g., "Shipwreck report #123 confirmed")
     */
    function freezeAddress(address target, string calldata reason) external {
        require(msg.sender == complianceOfficer, "Not authorized");
        isFrozen[target] = true;
        freezeReason[target] = reason;
        emit AddressFrozen(target, reason, block.timestamp);
    }

    /**
     * @notice Public disclosure (after court order)
     * @param target The address being disclosed
     * @param legalReference Court order or legal reference
     */
    function discloseAddress(address target, string calldata legalReference) external {
        require(msg.sender == complianceOfficer, "Not authorized");
        isDisclosed[target] = true;
        disclosureReference[target] = legalReference;
        emit AddressDisclosed(target, legalReference, block.timestamp);
    }
}
```

### Backend Compliance API

```typescript
// apps/api/app/controllers/compliance_controller.ts

export default class ComplianceController {
  /**
   * Handle law enforcement data request
   * Requires valid API key + legal documentation
   */
  async handleLawEnforcementRequest({ request, response }: HttpContext) {
    // 1. Verify requester is authorized agency
    const apiKey = request.header('X-LE-API-Key')
    const agency = await this.verifyAgency(apiKey)
    if (!agency) {
      return response.unauthorized({ error: 'Invalid agency credentials' })
    }

    // 2. Validate legal basis
    const { legalBasis, targetType, targetValue, requestedData } = request.body()
    const legalDoc = await this.validateLegalBasis(legalBasis)
    if (!legalDoc.valid) {
      return response.badRequest({ error: 'Invalid or expired legal basis' })
    }

    // 3. Log request (all requests logged for audit)
    await this.logRequest(agency, legalBasis, targetType, targetValue)

    // 4. Resolve identity chain
    const identityChain = await this.resolveIdentity(targetType, targetValue)

    // 5. Gather requested data
    const responseData: ComplianceResponse = {}

    if (requestedData.includes('identity')) {
      responseData.covenantSigner = identityChain.covenantSigner
      responseData.covenantSignedAt = identityChain.covenantSignedAt
    }

    if (requestedData.includes('transaction_history')) {
      responseData.poolDeposits = await this.getPoolDeposits(identityChain.addresses)
      responseData.poolWithdrawals = await this.getPoolWithdrawals(identityChain.addresses)
    }

    if (requestedData.includes('linked_addresses')) {
      responseData.derivedAddresses = await this.getAllDerivedAddresses(identityChain.metaAddress)
    }

    // 6. Return data
    return response.ok({
      requestId: crypto.randomUUID(),
      fulfilledAt: Date.now(),
      data: responseData,
    })
  }

  /**
   * Resolve any identifier to full identity chain
   */
  private async resolveIdentity(type: string, value: string): Promise<IdentityChain> {
    switch (type) {
      case 'address':
        // Stealth address → find which meta address derived it
        const fogWallet = await FogWallet.findBy('stealthAddress', value)
        if (fogWallet) {
          const covenant = await Covenant.findBy('stealthMetaAddress', fogWallet.metaAddress)
          return {
            stealthAddress: value,
            metaAddress: fogWallet.metaAddress,
            covenantSigner: covenant.signer,
            covenantSignedAt: covenant.signedAt,
          }
        }
        break

      case 'meta_address':
        const covenant = await Covenant.findBy('stealthMetaAddress', value)
        return {
          metaAddress: value,
          covenantSigner: covenant.signer,
          covenantSignedAt: covenant.signedAt,
          addresses: await this.getAllDerivedAddresses(value),
        }

      case 'port_name':
        const port = await Port.findBy('name', value)
        return {
          portName: value,
          metaAddress: port.stealthMetaAddress,
          covenantSigner: port.ownerAddress,
          // ... etc
        }
    }
  }
}
```

### Privacy vs Compliance Balance

```
┌─────────────────────────────────────────────────────────────────────┐
│                   GALEON'S PRIVACY MODEL                              │
├─────────────────────────────────────────────────────────────────────┤
│                                                                       │
│   WHAT THE PUBLIC SEES:                                               │
│   ──────────────────────                                              │
│   • Deposits into pool (amount, not source identity)                  │
│   • Withdrawals from pool (destination address only)                  │
│   • NO link between deposits and withdrawals                          │
│   • NO way to trace payments                                          │
│   → MAXIMUM PRIVACY FROM PUBLIC                                       │
│                                                                       │
│   ─────────────────────────────────────────────────────────────────  │
│                                                                       │
│   WHAT GALEON KNOWS:                                                  │
│   ───────────────────                                                 │
│   • Covenant signer (EOA) for every user                              │
│   • Which meta address belongs to which EOA                           │
│   • Which Ports belong to which user                                  │
│   • Pool deposit/withdrawal records                                   │
│   → CAN REVEAL WHEN LEGALLY REQUIRED                                  │
│                                                                       │
│   ─────────────────────────────────────────────────────────────────  │
│                                                                       │
│   WHEN DISCLOSURE HAPPENS:                                            │
│   ─────────────────────────                                           │
│   1. Confirmed Shipwreck report → Freeze + optional disclosure       │
│   2. Valid law enforcement request → Targeted disclosure              │
│   3. Court order → Full disclosure + public record                    │
│                                                                       │
│   ─────────────────────────────────────────────────────────────────  │
│                                                                       │
│   THE PROMISE:                                                        │
│   ─────────────                                                       │
│   "Your transactions are private from the world.                      │
│    But if you're a criminal, we can and will reveal you."            │
│                                                                       │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Why This Beats Tornado Cash

| Aspect                   | Tornado Cash            | Galeon Privacy Pools          |
| ------------------------ | ----------------------- | ----------------------------- |
| **Entry**                | Anonymous               | Covenant required             |
| **Bad actors**           | Welcome                 | Excluded                      |
| **Reporting**            | None                    | Built-in Shipwreck            |
| **Regulatory status**    | Sanctioned              | Compliant by design           |
| **If bad actor found**   | Pool sanctioned         | Actor excluded, pool survives |
| **User accountability**  | Zero                    | Signed attestation            |
| **Privacy quality**      | Maximum (all mixed)     | High (good actors only)       |
| **Sustainability**       | Dead (sanctioned)       | Alive (self-policing)         |
| **Law enforcement**      | No cooperation possible | Full cooperation capability   |
| **Selective disclosure** | Impossible              | Target one user, not all      |

### The Key Insight

> Tornado Cash was sanctioned because it couldn't exclude bad actors **or cooperate with law enforcement**.
>
> Galeon can exclude bad actors **and** reveal identities when legally required.
>
> Users get privacy from the public. Law enforcement gets cooperation. The pool survives.

---

## Architecture Summary

### v1 Architecture (0xbow Fork)

```
┌─────────────────────────────────────────────────────────────────────┐
│                    GALEON PRIVACY POOLS v1 (0xbow Fork)              │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│   PORT-ONLY DEPOSITS + ZK PROOFS                                     │
│   ──────────────────────────────                                     │
│                                                                      │
│   ┌──────────────┐                                                   │
│   │    PORT      │  ← Only source (covenant signers)                 │
│   │  Reception   │  ← Verified on-chain via GaleonRegistry           │
│   └──────┬───────┘                                                   │
│          │                                                           │
│          │ deposit(commitment) - Poseidon(nullifier, secret)         │
│          ▼                                                           │
│   ┌──────────────────────────────────────────────────────────────┐  │
│   │   PRIVACY POOL V1 (0xbow ZK)                                  │  │
│   │   ───────────────────────────                                 │  │
│   │                                                               │  │
│   │   • Fixed 1 MNT denomination                                  │  │
│   │   • Groth16 ZK proofs (BN254 curve)                          │  │
│   │   • Poseidon hash commitments                                 │  │
│   │   • Merkle tree (depth 20, ~1M deposits)                      │  │
│   │   • Nullifier-based double-spend prevention                   │  │
│   │   • 0xbow ASP system + Galeon ban list                        │  │
│   │   • Port-only deposits (on-chain enforced)                    │  │
│   │   • Stealth-only withdrawals (on-chain enforced)              │  │
│   └──────────────────────────────────────────────────────────────┘  │
│          │                                                           │
│          │ withdraw(proof, nullifier, recipient)                     │
│          │ ZK proof: "I know secret for commitment in tree"          │
│          ▼                                                           │
│   ┌──────────────┐                                                   │
│   │  FOG WALLET  │  ← Registered via registerWithdrawalAddress()    │
│   │  (stealth)   │  ← Cryptographically unlinked from deposit        │
│   └──────┬───────┘                                                   │
│          │                                                           │
│          │ Ready to pay (ZK-proven unlinkability)                    │
│          ▼                                                           │
│   ┌──────────────┐                                                   │
│   │   PAYMENT    │  ← Private payment from Fog wallet                │
│   └──────────────┘                                                   │
│                                                                      │
│   WHY 0xbow: Vitalik-backed, $6M+ volume, production-tested          │
│   Pool provides ZK mixing. Port funds are "pre-vetted".              │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### On-Chain Verification

**Port-Only Deposits** (GaleonRegistry v2):

```solidity
// GaleonRegistry tracks stealth addresses when payments are made
mapping(address => bool) public isPortStealthAddress;

// Updated in payNative/payToken:
isPortStealthAddress[stealthAddress] = true;

// Pool queries this:
require(galeonRegistry.isValidPortAddress(msg.sender), "Must deposit from Port");
```

**Fog Wallet Withdrawals** (Pool contract):

```solidity
// Users must register their Fog wallet address before withdrawing
function registerWithdrawalAddress(
    address stealthAddress,
    bytes calldata ephemeralPubKey,  // 33 bytes, compressed
    bytes1 viewTag
) external {
    require(ephemeralPubKey[0] == 0x02 || ephemeralPubKey[0] == 0x03);
    isValidWithdrawalAddress[stealthAddress] = true;
}

// Pool enforces (ensures withdrawal goes to a valid Fog wallet):
require(isValidWithdrawalAddress[recipient], "Must withdraw to Fog wallet");
```

### Full Vision Architecture (Future)

```
┌─────────────────────────────────────────────────────────────────────┐
│                    GALEON PRIVACY POOLS (Full Vision)                │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│   FUNDING SOURCES                                                    │
│   ───────────────                                                    │
│                                                                      │
│   ┌──────────────┐     ┌──────────────┐     ┌──────────────┐        │
│   │    PORT      │     │   EXTERNAL   │     │     CEX      │        │
│   │  (Preferred) │     │   Wallet     │     │  Withdrawal  │        │
│   └──────┬───────┘     └──────┬───────┘     └──────┬───────┘        │
│          │                    │                    │                 │
│          └────────────────────┼────────────────────┘                 │
│                               ▼                                      │
│                    ┌──────────────────────┐                          │
│                    │   PRIVACY POOL       │                          │
│                    │   (ZK-based)         │                          │
│                    │                      │                          │
│                    │  • Fixed denominations│                         │
│                    │  • Merkle tree of    │                          │
│                    │    deposits          │                          │
│                    │  • Association sets  │                          │
│                    │  • Chain analysis    │                          │
│                    └──────────┬───────────┘                          │
│                               │                                      │
│                               │ ZK Proof (Groth16)                   │
│                               ▼                                      │
│                    ┌──────────────────────┐                          │
│                    │   STEALTH ADDRESS    │                          │
│                    │   Ready to Pay       │                          │
│                    └──────────────────────┘                          │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Existing Infrastructure

### What We Have

| Component            | Status      | Location                                          |
| -------------------- | ----------- | ------------------------------------------------- |
| Stealth Addresses    | ✅ Complete | `packages/stealth/`                               |
| Ports (Receive)      | ✅ Complete | `apps/web/app/receive/`                           |
| Fog Wallets          | ✅ Complete | `apps/web/contexts/fog-context.tsx`               |
| Scheduled Payments   | ✅ Complete | `apps/web/contexts/scheduled-payment-context.tsx` |
| Scheduled Hops       | ✅ Complete | Same as above                                     |
| Privacy Calculations | ✅ Complete | `apps/web/lib/fog-privacy.ts`                     |
| Entry → Hop Flow     | ✅ Complete | Manual via AddHopModal                            |
| Auto-Hop on Funding  | 🔄 Planned  | In simplified UX plan                             |

### What We Need for v1 (0xbow Fork)

| Component                      | Priority | Complexity | Notes                                 |
| ------------------------------ | -------- | ---------- | ------------------------------------- |
| Fork 0xbow contracts           | High     | Medium     | Clone and adapt for Galeon            |
| GaleonRegistry v2              | High     | Low        | Add `isPortStealthAddress` tracking   |
| ZK Circuit integration         | High     | Medium     | Use 0xbow circuits, build for browser |
| Galeon-specific modifications  | High     | Medium     | Port-only deposits, stealth withdraw  |
| Port → Pool Deposit UI         | High     | Medium     | Generate commitment, store note       |
| Pool → Stealth Withdrawal UI   | High     | Medium     | ZK proof generation in browser        |
| Note Management (localStorage) | High     | Low        | Encrypted secret + nullifier storage  |
| Deploy to Mantle Sepolia       | High     | Low        | Verifier + Pool contracts             |

### What We Need for Future (v2+)

| Component                  | Priority | Complexity |
| -------------------------- | -------- | ---------- |
| Chain Analysis Integration | Future   | Medium     |
| Relayer Network            | Future   | High       |
| Multi-denomination Pools   | Future   | Medium     |
| ERC20 Token Pools          | Future   | Medium     |
| DAO Governance for ASP     | Future   | High       |

---

## Smart Contract Specification

### GaleonRegistryV1.sol (Upgradeable - UUPS)

> **Note**: GaleonRegistry integrates covenant storage directly - no separate GaleonCovenantRegistry contract needed. This simplifies architecture and reduces gas costs.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";

/// @title GaleonRegistryV1
/// @notice Central registry for Ports, Covenants, and Payments with revenue collection
/// @dev UUPS upgradeable - covenant storage integrated (no separate contract)
contract GaleonRegistryV1 is
    Initializable,
    UUPSUpgradeable,
    OwnableUpgradeable,
    ReentrancyGuardUpgradeable
{
    // ============================================================
    // CONSTANTS
    // ============================================================

    uint256 public constant SCHEME_ID = 1; // secp256k1
    uint256 public constant MAX_FEE_BPS = 500; // 5% max fee

    // ============================================================
    // STATE - Covenant (integrated, not separate contract)
    // ============================================================

    /// @notice Covenant version (increment on changes)
    uint256 public covenantVersion;

    /// @notice IPFS hash of current covenant text
    string public covenantIpfsHash;

    /// @notice User covenant signatures: user => version => signed
    mapping(address => mapping(uint256 => bool)) public hasSignedCovenant;

    /// @notice Timestamp of signature
    mapping(address => uint256) public covenantSignedAt;

    // ============================================================
    // STATE - Ports
    // ============================================================

    struct Port {
        bytes32 id;
        address owner;
        string name;
        bytes stealthMetaAddress; // 66 bytes: spending_pub (33) + viewing_pub (33)
        bool active;
        uint256 createdAt;
    }

    /// @notice Port by ID
    mapping(bytes32 => Port) public ports;

    /// @notice User's port IDs
    mapping(address => bytes32[]) public userPorts;

    // ============================================================
    // STATE - Payment Tracking (for Privacy Pool)
    // ============================================================

    /// @notice Track stealth addresses that received Port payments
    mapping(address => bool) public isPortStealthAddress;

    /// @notice Track verified balance per stealth address (for amount-limited deposits)
    mapping(address => uint256) public verifiedBalance;

    // ============================================================
    // STATE - Revenue Configuration
    // ============================================================

    /// @notice Treasury address for fees and donations
    address public treasury;

    /// @notice Port creation fee (wei) - Default: 0 during growth
    uint256 public portCreationFee;

    /// @notice Payment fee in basis points - Default: 0 during growth
    uint256 public paymentFeeBps;

    // ============================================================
    // EVENTS
    // ============================================================

    event CovenantUpdated(uint256 indexed version, string ipfsHash);
    event CovenantSigned(address indexed user, uint256 indexed version, uint256 timestamp);

    event PortRegistered(
        bytes32 indexed portId,
        address indexed owner,
        string name,
        bytes stealthMetaAddress
    );
    event PortDeactivated(bytes32 indexed portId);

    event PaymentReceived(
        address indexed stealthAddress,
        address indexed payer,
        uint256 amount,
        bytes32 receiptHash,
        uint256 fee
    );

    event ReceiptAnchored(
        address indexed stealthAddress,
        bytes32 indexed receiptHash,
        address indexed payer,
        uint256 amount,
        address token,
        uint256 timestamp
    );

    event FeesUpdated(uint256 portCreationFee, uint256 paymentFeeBps);
    event TreasuryUpdated(address indexed treasury);

    // ============================================================
    // INITIALIZER (replaces constructor for upgradeable)
    // ============================================================

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(
        address _owner,
        address _treasury,
        string calldata _covenantIpfsHash
    ) external initializer {
        __Ownable_init(_owner);
        __UUPSUpgradeable_init();
        __ReentrancyGuard_init();

        treasury = _treasury;
        covenantVersion = 1;
        covenantIpfsHash = _covenantIpfsHash;

        emit CovenantUpdated(1, _covenantIpfsHash);
    }

    // ============================================================
    // COVENANT FUNCTIONS
    // ============================================================

    /// @notice Sign the current covenant version
    function signCovenant() external {
        require(!hasSignedCovenant[msg.sender][covenantVersion], "Already signed");

        hasSignedCovenant[msg.sender][covenantVersion] = true;
        covenantSignedAt[msg.sender] = block.timestamp;

        emit CovenantSigned(msg.sender, covenantVersion, block.timestamp);
    }

    /// @notice Check if user has signed current covenant
    function hasValidCovenant(address user) public view returns (bool) {
        return hasSignedCovenant[user][covenantVersion];
    }

    /// @notice Update covenant (owner only) - requires re-signing
    function updateCovenant(string calldata _ipfsHash) external onlyOwner {
        covenantVersion++;
        covenantIpfsHash = _ipfsHash;
        emit CovenantUpdated(covenantVersion, _ipfsHash);
    }

    // ============================================================
    // PORT FUNCTIONS
    // ============================================================

    /// @notice Register a new Port (requires covenant signature)
    function registerPort(
        string calldata name,
        bytes calldata stealthMetaAddress
    ) external payable returns (bytes32 portId) {
        // Require covenant
        require(hasValidCovenant(msg.sender), "Must sign covenant first");

        // Require fee (if any)
        require(msg.value >= portCreationFee, "Insufficient fee");

        // Validate stealth meta address (66 bytes)
        require(stealthMetaAddress.length == 66, "Invalid stealth meta address");

        // Generate port ID
        portId = keccak256(abi.encodePacked(msg.sender, name, block.timestamp));
        require(ports[portId].id == bytes32(0), "Port already exists");

        // Store port
        ports[portId] = Port({
            id: portId,
            owner: msg.sender,
            name: name,
            stealthMetaAddress: stealthMetaAddress,
            active: true,
            createdAt: block.timestamp
        });

        userPorts[msg.sender].push(portId);

        // Collect fee
        if (msg.value > 0 && treasury != address(0)) {
            payable(treasury).transfer(msg.value);
        }

        emit PortRegistered(portId, msg.sender, name, stealthMetaAddress);
    }

    /// @notice Deactivate a Port (owner only)
    function deactivatePort(bytes32 portId) external {
        require(ports[portId].owner == msg.sender, "Not owner");
        require(ports[portId].active, "Already inactive");

        ports[portId].active = false;
        emit PortDeactivated(portId);
    }

    // ============================================================
    // PAYMENT FUNCTIONS
    // ============================================================

    /// @notice Pay native token (MNT) to a stealth address
    function payNative(
        address stealthAddress,
        bytes calldata ephemeralPubKey,
        uint8 viewTag,
        bytes32 receiptHash
    ) external payable nonReentrant {
        require(msg.value > 0, "No value");
        require(ephemeralPubKey.length == 33, "Invalid ephemeral key");

        // Calculate fee
        uint256 fee = (msg.value * paymentFeeBps) / 10000;
        uint256 netAmount = msg.value - fee;

        // Track for Privacy Pool integration
        isPortStealthAddress[stealthAddress] = true;
        verifiedBalance[stealthAddress] += netAmount;

        // Transfer to recipient
        payable(stealthAddress).transfer(netAmount);

        // Collect fee
        if (fee > 0 && treasury != address(0)) {
            payable(treasury).transfer(fee);
        }

        emit PaymentReceived(stealthAddress, msg.sender, netAmount, receiptHash, fee);
        emit ReceiptAnchored(
            stealthAddress,
            receiptHash,
            msg.sender,
            netAmount,
            address(0), // native token
            block.timestamp
        );
    }

    /// @notice Pay ERC-20 token to a stealth address
    /// @dev For hackathon: MNT-only pool. ERC-20 support tracks verifiedBalance but separate pools needed.
    function payToken(
        address token,
        address stealthAddress,
        uint256 amount,
        bytes calldata ephemeralPubKey,
        uint8 viewTag,
        bytes32 receiptHash
    ) external nonReentrant {
        require(amount > 0, "No amount");
        require(ephemeralPubKey.length == 33, "Invalid ephemeral key");

        // Calculate fee
        uint256 fee = (amount * paymentFeeBps) / 10000;
        uint256 netAmount = amount - fee;

        // Transfer from sender
        IERC20(token).transferFrom(msg.sender, stealthAddress, netAmount);
        if (fee > 0 && treasury != address(0)) {
            IERC20(token).transferFrom(msg.sender, treasury, fee);
        }

        // Track for Privacy Pool integration
        // NOTE: verifiedBalance is MNT-denominated for hackathon pool
        // Future: per-token verified balances for multi-token pools
        isPortStealthAddress[stealthAddress] = true;
        // verifiedBalance[stealthAddress] += netAmount; // Only for MNT pool

        emit PaymentReceived(stealthAddress, msg.sender, netAmount, receiptHash, fee);
        emit ReceiptAnchored(
            stealthAddress,
            receiptHash,
            msg.sender,
            netAmount,
            token,
            block.timestamp
        );
    }

    // ============================================================
    // VIEW FUNCTIONS (for Privacy Pool)
    // ============================================================

    /// @notice Check if address received a Port payment
    function isValidPortAddress(address addr) external view returns (bool) {
        return isPortStealthAddress[addr];
    }

    /// @notice Get verified balance for a stealth address
    function getVerifiedBalance(address stealthAddress) external view returns (uint256) {
        return verifiedBalance[stealthAddress];
    }

    // ============================================================
    // PRIVACY POOL INTEGRATION
    // ============================================================

    /// @notice Authorized Privacy Pool contract
    address public privacyPool;

    /// @notice Consume verified balance (called by Privacy Pool on deposit)
    /// @dev Only callable by the authorized Privacy Pool contract
    function consumeVerifiedBalance(address stealthAddress, uint256 amount) external {
        require(msg.sender == privacyPool, "Only Privacy Pool");
        require(verifiedBalance[stealthAddress] >= amount, "Insufficient verified balance");

        verifiedBalance[stealthAddress] -= amount;

        emit VerifiedBalanceConsumed(stealthAddress, amount);
    }

    /// @notice Set the authorized Privacy Pool contract
    function setPrivacyPool(address _privacyPool) external onlyOwner {
        require(_privacyPool != address(0), "Invalid pool");
        privacyPool = _privacyPool;
        emit PrivacyPoolUpdated(_privacyPool);
    }

    event VerifiedBalanceConsumed(address indexed stealthAddress, uint256 amount);
    event PrivacyPoolUpdated(address indexed privacyPool);

    // ============================================================
    // ADMIN FUNCTIONS
    // ============================================================

    /// @notice Update fee configuration
    function setFees(uint256 _portCreationFee, uint256 _paymentFeeBps) external onlyOwner {
        require(_paymentFeeBps <= MAX_FEE_BPS, "Fee too high");
        portCreationFee = _portCreationFee;
        paymentFeeBps = _paymentFeeBps;
        emit FeesUpdated(_portCreationFee, _paymentFeeBps);
    }

    /// @notice Update treasury address
    function setTreasury(address _treasury) external onlyOwner {
        require(_treasury != address(0), "Invalid treasury");
        treasury = _treasury;
        emit TreasuryUpdated(_treasury);
    }

    // ============================================================
    // UUPS UPGRADE
    // ============================================================

    /// @notice Authorize upgrade (owner only)
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}

    /// @notice Get implementation version
    function version() external pure returns (string memory) {
        return "1.0.0";
    }
}
```

**Key Integrations:**

| Feature                    | Purpose                                               |
| -------------------------- | ----------------------------------------------------- |
| `hasValidCovenant()`       | Gate Port creation, payment sending                   |
| `isPortStealthAddress`     | Verify deposits to Privacy Pool came from Ports       |
| `verifiedBalance`          | Track clean funds per stealth address                 |
| `consumeVerifiedBalance()` | Pool calls on deposit to deduct from verified balance |
| `portCreationFee`          | Revenue from Port creation                            |
| `paymentFeeBps`            | Revenue from payments                                 |
| UUPS Upgradeable           | Future-proof contract upgrades                        |

### GaleonPrivacyPool.sol (v1 - 0xbow Fork)

> **Note**: This is based on forking 0xbow's privacy-pools-core contracts and adding Galeon-specific modifications.

**Key Modifications to 0xbow:**

```solidity
// GALEON ADDITION 1: Port-only + Amount-limited deposits
IGaleonRegistry public immutable galeonRegistry;

// Track who deposited each commitment (for freeze capability)
mapping(bytes32 => address) public commitmentDepositor;

function deposit(bytes32 commitment) external payable {
    // 0xbow standard checks
    require(msg.value == DENOMINATION, "Invalid amount");
    require(!commitments[commitment], "Duplicate commitment");

    // GALEON: Port-only deposits (must have received payment via GaleonRegistry)
    require(
        galeonRegistry.isValidPortAddress(msg.sender),
        "Depositor must be a Port stealth address"
    );

    // GALEON: Amount-limited deposits (only verified "clean" funds)
    require(
        galeonRegistry.getVerifiedBalance(msg.sender) >= msg.value,
        "Amount exceeds verified balance"
    );

    // Consume verified balance (prevents depositing dirty funds)
    galeonRegistry.consumeVerifiedBalance(msg.sender, msg.value);

    // Track depositor for compliance/freeze capability
    commitmentDepositor[commitment] = msg.sender;

    // Rest of 0xbow deposit logic...
    _insert(commitment);
    commitments[commitment] = true;
    emit Deposit(commitment, leafIndex, block.timestamp, msg.sender);
}

// GALEON ADDITION 2: Stealth-only withdrawals
mapping(address => bool) public isValidWithdrawalAddress;

function registerWithdrawalAddress(
    address stealthAddress,
    bytes calldata ephemeralPubKey,
    bytes1 viewTag
) external {
    require(ephemeralPubKey.length == 33, "Invalid key length");
    require(ephemeralPubKey[0] == 0x02 || ephemeralPubKey[0] == 0x03, "Invalid prefix");

    isValidWithdrawalAddress[stealthAddress] = true;
    emit WithdrawalAddressRegistered(stealthAddress, ephemeralPubKey, viewTag);
}

/// @notice Withdraw from pool with ZK proof
/// @dev The ZK proof proves knowledge of (nullifier, secret) such that:
///      1. commitment = Poseidon(nullifier, secret) exists in Merkle tree at `root`
///      2. nullifierHash = Poseidon(nullifier) (public, prevents double-spend)
///      3. commitment is in the valid association set (ASP root)
///      The commitment itself is NEVER revealed - only proven via ZK.
function withdraw(
    bytes calldata proof,         // Groth16 proof
    bytes32 root,                 // Merkle root (proves membership)
    bytes32 aspRoot,              // Association set root (proves not excluded)
    bytes32 nullifierHash,        // Poseidon(nullifier) - public, prevents double-spend
    address payable recipient,    // Where to send funds
    address relayer,              // Optional relayer (pays gas, receives fee)
    uint256 relayerFee,           // Fee for relayer (deducted from withdrawal)
    uint256 donationBps           // Optional donation to treasury (0-1000 = 0-10%)
) external nonReentrant {
    // GALEON: Stealth-only withdrawals
    require(isValidWithdrawalAddress[recipient], "Must withdraw to stealth address");

    // Prevent double-spend
    require(!nullifierHashes[nullifierHash], "Already spent");
    nullifierHashes[nullifierHash] = true;

    // Verify merkle root is known (recent)
    require(isKnownRoot(root), "Invalid merkle root");

    // Verify ASP root matches current valid set
    require(aspRoot == currentASPRoot, "Invalid ASP root");

    // Verify ZK proof
    // Public inputs: [root, aspRoot, nullifierHash, recipient, relayer, relayerFee]
    // The proof validates that the prover knows (nullifier, secret, pathElements)
    // such that Poseidon(nullifier, secret) is in the tree AND valid set
    uint256[6] memory publicInputs = [
        uint256(root),
        uint256(aspRoot),
        uint256(nullifierHash),
        uint256(uint160(recipient)),
        uint256(uint160(relayer)),
        relayerFee
    ];
    require(verifier.verifyProof(proof, publicInputs), "Invalid ZK proof");

    // Calculate amounts
    uint256 protocolFee = (DENOMINATION * withdrawalFeeBps) / 10000;
    uint256 donation = (DENOMINATION * donationBps) / 10000;
    uint256 netAmount = DENOMINATION - protocolFee - donation - relayerFee;

    // Distribute funds
    if (relayerFee > 0 && relayer != address(0)) {
        payable(relayer).transfer(relayerFee);
    }
    if (protocolFee + donation > 0) {
        payable(treasury).transfer(protocolFee + donation);
    }
    payable(recipient).transfer(netAmount);

    emit Withdrawal(recipient, nullifierHash, relayer, relayerFee, protocolFee, donation);
}
```

**ZK Proof Structure (Groth16):**

```
Private Inputs (known only to prover):
├── nullifier         (random 32 bytes, part of commitment)
├── secret            (random 32 bytes, part of commitment)
├── pathElements[20]  (Merkle proof siblings)
├── pathIndices[20]   (left/right path indicators)
└── aspPathElements   (ASP membership proof)

Public Inputs (visible to verifier/contract):
├── root              (Merkle root)
├── aspRoot           (Association set root)
├── nullifierHash     (Poseidon(nullifier))
├── recipient         (withdrawal address)
├── relayer           (relayer address)
└── relayerFee        (relayer compensation)

Circuit proves:
1. commitment = Poseidon(nullifier, secret)
2. commitment is in Merkle tree at root
3. commitment is in ASP valid set at aspRoot
4. nullifierHash = Poseidon(nullifier)

The commitment is NEVER revealed - ZK proves it exists without showing which one.
```

### 0xbow Contracts to Fork

| Contract                    | Purpose                 | Modifications                      |
| --------------------------- | ----------------------- | ---------------------------------- |
| `PrivacyPool.sol`           | Main pool logic         | Add Port-only, stealth-only checks |
| `Verifier.sol`              | Groth16 verifier        | None (use as-is)                   |
| `MerkleTreeWithHistory.sol` | Incremental Merkle tree | None (use as-is)                   |
| `Poseidon.sol`              | ZK-friendly hash        | None (use as-is)                   |

### GaleonPrivacyPoolV0.sol (Fallback - Commit-Reveal)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

interface IGaleonRegistry {
    function isValidPortAddress(address addr) external view returns (bool);
}

/// @title GaleonPrivacyPoolV0
/// @notice Privacy pool with commit-reveal mixing (v0, no ZK)
/// @dev Port-only deposits, stealth-only withdrawals, 2-hour timelock
contract GaleonPrivacyPoolV0 is ReentrancyGuard {
    // ============================================================
    // CONSTANTS
    // ============================================================

    uint256 public constant DENOMINATION = 1 ether; // 1 MNT per deposit
    uint256 public constant MIN_TIMELOCK = 2 hours; // Minimum delay for anonymity

    // ============================================================
    // STATE
    // ============================================================

    struct Deposit {
        bytes32 commitment;    // hash(secret)
        uint256 depositedAt;   // timestamp
        bool withdrawn;        // prevent double-withdraw
    }

    // Immutable references
    IGaleonRegistry public immutable galeonRegistry;
    address public owner;

    // Core state
    mapping(uint256 => Deposit) public deposits;
    uint256 public depositCount;

    // ASP v0: Simple ban list (owner-controlled)
    mapping(address => bool) public isBanned;

    // Stealth withdrawal verification
    mapping(address => bool) public isValidWithdrawalAddress;

    // ============================================================
    // EVENTS
    // ============================================================

    event Deposited(
        uint256 indexed index,
        bytes32 commitment,
        address indexed depositor,
        uint256 timestamp
    );

    event Withdrawn(
        uint256 indexed index,
        address indexed recipient,
        uint256 timestamp
    );

    event WithdrawalAddressRegistered(
        address indexed stealthAddress,
        bytes ephemeralPubKey,
        bytes1 viewTag
    );

    event AddressBanned(address indexed target, string reason);
    event AddressUnbanned(address indexed target);

    // ============================================================
    // CONSTRUCTOR
    // ============================================================

    constructor(address _galeonRegistry, address _owner) {
        require(_galeonRegistry != address(0), "Invalid registry");
        require(_owner != address(0), "Invalid owner");
        galeonRegistry = IGaleonRegistry(_galeonRegistry);
        owner = _owner;
    }

    // ============================================================
    // STEALTH WITHDRAWAL REGISTRATION
    // ============================================================

    /// @notice Register a stealth address for withdrawal
    /// @dev Must be called before withdraw(), validates ephemeral key format
    /// @param stealthAddress The stealth address to register
    /// @param ephemeralPubKey The ephemeral public key (33 bytes, compressed)
    /// @param viewTag The view tag for scanning
    function registerWithdrawalAddress(
        address stealthAddress,
        bytes calldata ephemeralPubKey,
        bytes1 viewTag
    ) external {
        require(stealthAddress != address(0), "Invalid stealth address");
        require(ephemeralPubKey.length == 33, "Invalid ephemeral key length");
        require(
            ephemeralPubKey[0] == 0x02 || ephemeralPubKey[0] == 0x03,
            "Invalid pubkey prefix"
        );
        require(!isValidWithdrawalAddress[stealthAddress], "Already registered");

        isValidWithdrawalAddress[stealthAddress] = true;
        emit WithdrawalAddressRegistered(stealthAddress, ephemeralPubKey, viewTag);
    }

    // ============================================================
    // CORE POOL FUNCTIONS
    // ============================================================

    /// @notice Deposit funds into the pool
    /// @dev Only Port stealth addresses can deposit (enforced on-chain)
    /// @param commitment Hash of the secret (keccak256(secret))
    function deposit(bytes32 commitment) external payable nonReentrant {
        require(msg.value == DENOMINATION, "Must deposit exactly 1 MNT");
        require(commitment != bytes32(0), "Invalid commitment");
        require(
            galeonRegistry.isValidPortAddress(msg.sender),
            "Must deposit from Port address"
        );
        require(!isBanned[msg.sender], "Address is banned");

        uint256 index = depositCount++;
        deposits[index] = Deposit({
            commitment: commitment,
            depositedAt: block.timestamp,
            withdrawn: false
        });

        emit Deposited(index, commitment, msg.sender, block.timestamp);
    }

    /// @notice Withdraw funds from the pool
    /// @dev Requires timelock expired, valid secret, and registered stealth address
    /// @param depositIndex The index of the deposit to withdraw
    /// @param secret The original secret (hash must match commitment)
    /// @param recipient The registered stealth address to receive funds
    function withdraw(
        uint256 depositIndex,
        bytes32 secret,
        address payable recipient
    ) external nonReentrant {
        Deposit storage d = deposits[depositIndex];

        require(!d.withdrawn, "Already withdrawn");
        require(
            block.timestamp >= d.depositedAt + MIN_TIMELOCK,
            "Timelock not expired"
        );
        require(
            keccak256(abi.encodePacked(secret)) == d.commitment,
            "Invalid secret"
        );
        require(
            isValidWithdrawalAddress[recipient],
            "Must withdraw to registered stealth address"
        );
        require(!isBanned[recipient], "Recipient is banned");

        d.withdrawn = true;

        (bool success, ) = recipient.call{value: DENOMINATION}("");
        require(success, "Transfer failed");

        emit Withdrawn(depositIndex, recipient, block.timestamp);
    }

    // ============================================================
    // ASP V0: BAN LIST (Owner Only)
    // ============================================================

    /// @notice Ban an address from deposits and withdrawals
    function ban(address target, string calldata reason) external {
        require(msg.sender == owner, "Only owner");
        require(target != address(0), "Invalid address");
        isBanned[target] = true;
        emit AddressBanned(target, reason);
    }

    /// @notice Unban an address
    function unban(address target) external {
        require(msg.sender == owner, "Only owner");
        isBanned[target] = false;
        emit AddressUnbanned(target);
    }

    /// @notice Transfer ownership
    function transferOwnership(address newOwner) external {
        require(msg.sender == owner, "Only owner");
        require(newOwner != address(0), "Invalid new owner");
        owner = newOwner;
    }

    // ============================================================
    // VIEW FUNCTIONS
    // ============================================================

    function getDeposit(uint256 index) external view returns (
        bytes32 commitment,
        uint256 depositedAt,
        bool withdrawn
    ) {
        Deposit storage d = deposits[index];
        return (d.commitment, d.depositedAt, d.withdrawn);
    }

    function canWithdraw(uint256 depositIndex) external view returns (bool) {
        Deposit storage d = deposits[depositIndex];
        return !d.withdrawn && block.timestamp >= d.depositedAt + MIN_TIMELOCK;
    }

    function getPoolStats() external view returns (
        uint256 totalDeposits,
        uint256 denomination,
        uint256 timelock
    ) {
        return (depositCount, DENOMINATION, MIN_TIMELOCK);
    }
}
```

### GaleonPrivacyPool.sol (Full Vision - ZK-based with Compliance)

> **Note**: This is the full implementation with ZK proofs and compliance features.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

interface IVerifier {
    function verifyProof(
        uint256[2] memory a,
        uint256[2][2] memory b,
        uint256[2] memory c,
        uint256[4] memory input
    ) external view returns (bool);
}

interface IGaleonRegistry {
    function isValidPortAddress(address addr) external view returns (bool);
}

contract GaleonPrivacyPool is ReentrancyGuard, Ownable {
    // ============================================================
    // CONSTANTS
    // ============================================================

    uint256 public constant DENOMINATION = 1 ether; // 1 MNT per deposit
    uint32 public constant MERKLE_TREE_HEIGHT = 20; // ~1M deposits
    uint256 public constant APPEAL_PERIOD = 30 days;

    // ============================================================
    // STATE
    // ============================================================

    // External contracts
    IGaleonRegistry public immutable galeonRegistry;
    IVerifier public withdrawVerifier;

    // Deposit tracking
    bytes32 public depositRoot;
    uint256 public depositCount;
    mapping(uint256 => bytes32) public depositHashes; // index => commitment

    // COMPLIANCE: Track verified balances from GaleonRegistry
    mapping(address => uint256) public verifiedBalance;

    // COMPLIANCE: Track who deposited each commitment (for freeze capability)
    mapping(bytes32 => address) public commitmentDepositor;
    mapping(bytes32 => uint256) public commitmentAmount;

    // COMPLIANCE: Exclusion system for bad actors
    struct Exclusion {
        bool excluded;
        uint256 excludedAt;
        uint256 amount;
        address depositor;
    }
    mapping(bytes32 => Exclusion) public exclusions;
    mapping(bytes32 => bool) public frozenClaimed;

    // Treasury for recovered frozen funds
    address public treasury;

    // Association Set Providers
    mapping(address => bytes32) public aspRoots;
    mapping(address => bool) public isApprovedASP;
    address public defaultASP;

    // Nullifiers (prevent double-spend)
    mapping(bytes32 => bool) public nullifiers;

    // Stealth withdrawal addresses
    mapping(address => bool) public isValidWithdrawalAddress;

    // ============================================================
    // EVENTS
    // ============================================================

    event Deposit(
        bytes32 indexed commitment,
        address indexed depositor,
        uint256 amount,
        uint256 leafIndex,
        uint256 timestamp
    );

    event Withdrawal(
        address indexed recipient,
        bytes32 nullifierHash,
        address asp,
        uint256 timestamp
    );

    event WithdrawalAddressRegistered(
        address indexed stealthAddress,
        bytes ephemeralPubKey,
        bytes1 viewTag
    );

    event VerifiedPaymentRecorded(
        address indexed stealthAddress,
        uint256 amount
    );

    event CommitmentExcluded(
        bytes32 indexed commitment,
        address indexed depositor
    );

    event ExclusionRemoved(bytes32 indexed commitment);

    event FrozenFundsClaimed(
        bytes32 indexed commitment,
        uint256 amount
    );

    event ASPRootUpdated(
        address indexed asp,
        bytes32 newRoot,
        uint256 timestamp
    );

    // ============================================================
    // CONSTRUCTOR
    // ============================================================

    constructor(
        address _galeonRegistry,
        address _treasury,
        address _owner
    ) Ownable(_owner) {
        require(_galeonRegistry != address(0), "Invalid registry");
        require(_treasury != address(0), "Invalid treasury");
        galeonRegistry = IGaleonRegistry(_galeonRegistry);
        treasury = _treasury;
    }

    // ============================================================
    // VERIFIED BALANCE TRACKING
    // ============================================================

    /**
     * @notice Record a verified payment from GaleonRegistry
     * @dev Only callable by GaleonRegistry after payNative/payToken
     * @param stealthAddress The stealth address that received payment
     * @param amount The amount received
     */
    function recordVerifiedPayment(
        address stealthAddress,
        uint256 amount
    ) external {
        require(msg.sender == address(galeonRegistry), "Only registry");
        verifiedBalance[stealthAddress] += amount;
        emit VerifiedPaymentRecorded(stealthAddress, amount);
    }

    // ============================================================
    // STEALTH WITHDRAWAL REGISTRATION
    // ============================================================

    /**
     * @notice Register a stealth address for withdrawal
     * @param stealthAddress The stealth address to register
     * @param ephemeralPubKey The ephemeral public key (33 bytes)
     * @param viewTag The view tag for scanning
     */
    function registerWithdrawalAddress(
        address stealthAddress,
        bytes calldata ephemeralPubKey,
        bytes1 viewTag
    ) external {
        require(stealthAddress != address(0), "Invalid address");
        require(ephemeralPubKey.length == 33, "Invalid key length");
        require(
            ephemeralPubKey[0] == 0x02 || ephemeralPubKey[0] == 0x03,
            "Invalid pubkey prefix"
        );

        isValidWithdrawalAddress[stealthAddress] = true;
        emit WithdrawalAddressRegistered(stealthAddress, ephemeralPubKey, viewTag);
    }

    // ============================================================
    // DEPOSIT
    // ============================================================

    /**
     * @notice Deposit MNT into the pool
     * @dev Only Port addresses with verified balance can deposit
     * @param commitment Hash of (secret, nullifier)
     */
    function deposit(bytes32 commitment) external payable nonReentrant {
        require(msg.value > 0, "Zero deposit");
        require(commitment != bytes32(0), "Invalid commitment");

        // COMPLIANCE: Only Port addresses can deposit
        require(
            galeonRegistry.isValidPortAddress(msg.sender),
            "Must deposit from Port"
        );

        // COMPLIANCE: Only verified amounts can be deposited (prevents dusting)
        require(
            verifiedBalance[msg.sender] >= msg.value,
            "Exceeds verified balance"
        );

        // Deduct from verified balance
        verifiedBalance[msg.sender] -= msg.value;

        // COMPLIANCE: Track depositor for freeze capability
        commitmentDepositor[commitment] = msg.sender;
        commitmentAmount[commitment] = msg.value;

        // Add to merkle tree
        uint256 leafIndex = depositCount;
        depositHashes[leafIndex] = commitment;
        depositRoot = _insertLeaf(commitment);
        depositCount++;

        emit Deposit(commitment, msg.sender, msg.value, leafIndex, block.timestamp);
    }

    // ============================================================
    // WITHDRAWAL
    // ============================================================

    /**
     * @notice Withdraw from the pool with ZK proof
     * @param proof ZK proof of valid deposit
     * @param nullifierHash Unique identifier to prevent double-spend
     * @param recipient Registered stealth address to receive funds
     * @param asp Association Set Provider to use (0 = default)
     */
    function withdraw(
        bytes calldata proof,
        bytes32 nullifierHash,
        address payable recipient,
        address asp
    ) external nonReentrant {
        require(!nullifiers[nullifierHash], "Already withdrawn");
        require(recipient != address(0), "Invalid recipient");

        // COMPLIANCE: Only registered stealth addresses
        require(
            isValidWithdrawalAddress[recipient],
            "Must withdraw to registered stealth"
        );

        // Use default ASP if none specified
        address effectiveASP = asp == address(0) ? defaultASP : asp;
        require(isApprovedASP[effectiveASP], "ASP not approved");

        bytes32 aspRoot = aspRoots[effectiveASP];
        require(aspRoot != bytes32(0), "ASP has no root");

        // Verify ZK proof (includes exclusion set check)
        bool valid = _verifyWithdrawProof(
            proof,
            depositRoot,
            aspRoot,
            nullifierHash,
            recipient
        );
        require(valid, "Invalid proof");

        // Mark nullifier as used
        nullifiers[nullifierHash] = true;

        // Transfer funds
        (bool success, ) = recipient.call{value: DENOMINATION}("");
        require(success, "Transfer failed");

        emit Withdrawal(recipient, nullifierHash, effectiveASP, block.timestamp);
    }

    // ============================================================
    // COMPLIANCE: EXCLUSION SYSTEM
    // ============================================================

    /**
     * @notice Exclude a commitment (freeze bad actor's funds)
     * @dev Only callable by approved ASP
     * @param commitment The commitment to exclude
     */
    function excludeCommitment(bytes32 commitment) external {
        require(isApprovedASP[msg.sender], "Not approved ASP");
        require(commitmentDepositor[commitment] != address(0), "Unknown commitment");
        require(!exclusions[commitment].excluded, "Already excluded");

        exclusions[commitment] = Exclusion({
            excluded: true,
            excludedAt: block.timestamp,
            amount: commitmentAmount[commitment],
            depositor: commitmentDepositor[commitment]
        });

        emit CommitmentExcluded(commitment, commitmentDepositor[commitment]);
    }

    /**
     * @notice Remove exclusion (appeal successful)
     * @dev Only callable by approved ASP
     * @param commitment The commitment to un-exclude
     */
    function removeExclusion(bytes32 commitment) external {
        require(isApprovedASP[msg.sender], "Not approved ASP");
        require(exclusions[commitment].excluded, "Not excluded");

        exclusions[commitment].excluded = false;
        emit ExclusionRemoved(commitment);
    }

    /**
     * @notice Claim frozen funds after appeal period
     * @dev Only callable by approved ASP, funds go to treasury
     * @param commitment The commitment with frozen funds
     */
    function claimFrozenFunds(bytes32 commitment) external {
        require(isApprovedASP[msg.sender], "Not approved ASP");

        Exclusion memory exc = exclusions[commitment];
        require(exc.excluded, "Not excluded");
        require(
            block.timestamp >= exc.excludedAt + APPEAL_PERIOD,
            "Appeal period active"
        );
        require(!frozenClaimed[commitment], "Already claimed");

        frozenClaimed[commitment] = true;

        (bool success, ) = treasury.call{value: exc.amount}("");
        require(success, "Transfer failed");

        emit FrozenFundsClaimed(commitment, exc.amount);
    }

    /**
     * @notice Check if a commitment is excluded
     * @param commitment The commitment to check
     * @return True if excluded
     */
    function isExcluded(bytes32 commitment) external view returns (bool) {
        return exclusions[commitment].excluded;
    }

    // ============================================================
    // ASP MANAGEMENT
    // ============================================================

    function updateASPRoot(bytes32 newRoot) external {
        require(isApprovedASP[msg.sender], "Not an approved ASP");
        aspRoots[msg.sender] = newRoot;
        emit ASPRootUpdated(msg.sender, newRoot, block.timestamp);
    }

    function approveASP(address asp) external onlyOwner {
        isApprovedASP[asp] = true;
    }

    function revokeASP(address asp) external onlyOwner {
        isApprovedASP[asp] = false;
    }

    function setDefaultASP(address asp) external onlyOwner {
        require(isApprovedASP[asp], "ASP not approved");
        defaultASP = asp;
    }

    function setTreasury(address _treasury) external onlyOwner {
        require(_treasury != address(0), "Invalid treasury");
        treasury = _treasury;
    }

    // ============================================================
    // VIEW FUNCTIONS
    // ============================================================

    function getDepositRoot() external view returns (bytes32) {
        return depositRoot;
    }

    function getASPRoot(address asp) external view returns (bytes32) {
        return aspRoots[asp];
    }

    function isNullifierUsed(bytes32 nullifier) external view returns (bool) {
        return nullifiers[nullifier];
    }

    function getVerifiedBalance(address addr) external view returns (uint256) {
        return verifiedBalance[addr];
    }

    function getExclusion(bytes32 commitment) external view returns (
        bool excluded,
        uint256 excludedAt,
        uint256 amount,
        address depositor,
        bool claimed
    ) {
        Exclusion memory exc = exclusions[commitment];
        return (
            exc.excluded,
            exc.excludedAt,
            exc.amount,
            exc.depositor,
            frozenClaimed[commitment]
        );
    }

    // ============================================================
    // INTERNAL
    // ============================================================

    function _insertLeaf(bytes32 leaf) internal returns (bytes32) {
        // Simplified - real implementation uses incremental merkle tree
        // See tornado-core for reference implementation
        return keccak256(abi.encodePacked(depositRoot, leaf, depositCount));
    }

    function _verifyWithdrawProof(
        bytes calldata proof,
        bytes32 _depositRoot,
        bytes32 _aspRoot,
        bytes32 _nullifierHash,
        address _recipient
    ) internal view returns (bool) {
        // Decode and verify using Groth16 verifier
        // The ZK circuit proves:
        // 1. User knows (secret, nullifier) for a commitment in the deposit tree
        // 2. That commitment is NOT in the exclusion set
        // 3. nullifierHash = hash(nullifier)
        // Implementation depends on ZK circuit
        return true; // Placeholder - replace with actual verifier call
    }
}
```

---

## ZK Circuit Specification

### Withdrawal Circuit

**Private Inputs:**

- `secret` - Random value known only to depositor
- `nullifier` - Random value for preventing double-spend
- `pathElements` - Merkle proof elements for deposit tree
- `pathIndices` - Merkle proof path (0 = left, 1 = right)
- `aspPathElements` - Merkle proof elements for ASP tree
- `aspPathIndices` - ASP merkle proof path

**Public Inputs:**

- `depositRoot` - Current deposit merkle root
- `aspRoot` - ASP's association set merkle root
- `nullifierHash` - Hash of nullifier (public for double-spend prevention)
- `recipient` - Withdrawal address

**Constraints:**

```
1. commitment = hash(secret, nullifier)
2. nullifierHash = hash(nullifier)
3. MerkleProof(commitment, pathElements, pathIndices) == depositRoot
4. MerkleProof(commitment, aspPathElements, aspPathIndices) == aspRoot
```

### Circuit Files Needed

| File                         | Purpose                    |
| ---------------------------- | -------------------------- |
| `circuits/withdraw.circom`   | Main withdrawal circuit    |
| `circuits/merkleTree.circom` | Merkle tree verification   |
| `circuits/poseidon.circom`   | Poseidon hash function     |
| `contracts/Verifier.sol`     | Generated Groth16 verifier |

---

## Association Set Provider (ASP)

### Galeon ASP Service

```typescript
// packages/asp/src/galeon-asp.ts

interface GaleonASP {
  // Core functionality
  isDepositGood(depositAddress: Address): Promise<boolean>
  buildAssociationTree(deposits: Deposit[]): MerkleTree
  getRoot(): bytes32
  getProof(commitment: bytes32): MerkleProof

  // Monitoring
  monitorNewDeposits(): void
  checkSanctionsList(address: Address): boolean
}

// Simple implementation
class GaleonASPService implements GaleonASP {
  private sanctionsList: Set<Address>
  private badActors: Set<Address>
  private goodDeposits: Map<bytes32, Deposit>
  private merkleTree: MerkleTree

  async isDepositGood(depositAddress: Address): Promise<boolean> {
    // Check OFAC sanctions
    if (this.sanctionsList.has(depositAddress.toLowerCase())) {
      return false
    }

    // Check known bad actors
    if (this.badActors.has(depositAddress.toLowerCase())) {
      return false
    }

    // Everything else is good
    return true
  }

  async processNewDeposit(event: DepositEvent): Promise<void> {
    const { commitment, depositor } = event

    if (await this.isDepositGood(depositor)) {
      this.goodDeposits.set(commitment, event)
      this.rebuildTree()
      await this.updateOnChainRoot()
    }
  }

  private rebuildTree(): void {
    const leaves = Array.from(this.goodDeposits.keys())
    this.merkleTree = new MerkleTree(leaves, poseidon)
  }

  private async updateOnChainRoot(): Promise<void> {
    const root = this.merkleTree.root
    await this.contract.updateASPRoot(root)
  }
}
```

---

## Implementation Phases

### v1 Implementation (0xbow Fork)

#### Phase 1: Fork & Adapt Contracts (3-4 days)

**Deliverables:**

- [ ] Clone 0xbow privacy-pools-core contracts
- [ ] Update `GaleonRegistry.sol` with `isPortStealthAddress` tracking
- [ ] Add Port-only deposits to forked PrivacyPool.sol
- [ ] Add stealth-only withdrawals (registerWithdrawalAddress)
- [ ] Deployment scripts for Mantle Sepolia
- [ ] Integration tests

**Checkpoints:**

- [ ] 0xbow contracts compile on Mantle
- [ ] GaleonRegistry tracks stealth addresses on payment
- [ ] Pool only accepts deposits from tracked Port addresses
- [ ] Poseidon commitment stored correctly
- [ ] Stealth address registration works
- [ ] Verifier contract deployed and working

#### Phase 2: ZK Circuit Integration (2-3 days)

**Deliverables:**

- [ ] Copy 0xbow Circom circuits
- [ ] Generate proving key (use 0xbow trusted setup)
- [ ] Build circuit artifacts for browser (wasm + zkey)
- [ ] Integrate snarkjs for proof generation
- [ ] Test proof generation in browser

**Files:**

```
packages/circuits/
├── withdraw.circom                 # 0xbow circuit
├── poseidon.circom                 # Poseidon hash
├── merkleProof.circom              # Merkle proof
└── build/
    ├── withdraw.wasm
    ├── withdraw_final.zkey
    └── verification_key.json
```

**Checkpoints:**

- [ ] Circuit compiles with circom
- [ ] Proof generation works in browser (<30s)
- [ ] Proof verification on-chain succeeds
- [ ] Invalid proofs are rejected

#### Phase 3: Frontend Integration (2-3 days)

**Files to create:**
| File | Purpose |
|------|---------|
| `apps/web/contexts/pool-context.tsx` | Pool state + operations |
| `apps/web/hooks/use-pool-deposit.ts` | Deposit from Port |
| `apps/web/hooks/use-pool-withdraw.ts` | ZK proof + withdraw |
| `apps/web/lib/zk-prover.ts` | snarkjs integration |
| `apps/web/components/pool/deposit-modal.tsx` | Deposit UI |
| `apps/web/components/pool/withdraw-modal.tsx` | Withdraw UI |
| `apps/web/components/pool/pool-status-card.tsx` | Pool stats |

**Checkpoints:**

- [ ] User can deposit from Port UI
- [ ] Note (secret + nullifier) stored encrypted in localStorage
- [ ] User can see pending deposits + anonymity set size
- [ ] User can register withdrawal stealth address
- [ ] ZK proof generation in browser works
- [ ] User can withdraw with valid proof
- [ ] Full flow works end-to-end

#### Phase 4: Note Management (1 day)

**Note storage (like Tornado Cash):**

```typescript
interface PoolNote {
  currency: 'MNT'
  amount: string
  netId: number // Chain ID
  commitment: `0x${string}`
  nullifier: `0x${string}`
  secret: `0x${string}`
  leafIndex: number
  depositedAt: number
}

// Serialized format for backup
// galeon-mnt-1-0x<commitment>-0x<nullifier>-0x<secret>

// Encrypted in localStorage with session key
const POOL_NOTES_KEY = 'galeon-pool-notes-{address}'
```

**Checkpoints:**

- [ ] Notes encrypted at rest
- [ ] Backup/export flow works
- [ ] Note format is portable

#### Phase 5: Testing & Deploy (2 days)

**Checkpoints:**

- [ ] Deposit from Port succeeds
- [ ] Deposit from non-Port fails
- [ ] Withdrawal with valid proof succeeds
- [ ] Withdrawal with invalid proof fails
- [ ] Double-spend (same nullifier) fails
- [ ] Invalid root fails
- [ ] Stealth address registration works
- [ ] Full flow: Port → Pool → Fog → Pay
- [ ] Testnet deployment verified

---

### Full Vision Implementation (Future)

> These phases are deferred until after v0 is working.

#### Phase A: ZK Circuits

**Deliverables:**

- [ ] `withdraw.circom` - Withdrawal circuit
- [ ] `merkleTree.circom` - Merkle proof verification
- [ ] Trusted setup ceremony (or use existing)
- [ ] `Verifier.sol` - Generated verifier contract
- [ ] Circuit tests

**Checkpoints:**

- [ ] Circuit compiles with circom
- [ ] Witness generation works
- [ ] Proof generation < 30 seconds
- [ ] Proof verification on-chain succeeds
- [ ] Invalid proofs are rejected

#### Phase B: ASP Backend

**Deliverables:**

- [ ] ASP service in `apps/api/`
- [ ] Deposit event listener
- [ ] Sanctions list integration (OFAC API)
- [ ] Association tree maintenance
- [ ] On-chain root updates
- [ ] REST API for proof generation

**Checkpoints:**

- [ ] ASP detects new deposits within 1 minute
- [ ] Good deposits added to association tree
- [ ] Bad deposits excluded
- [ ] Root updates on-chain
- [ ] API returns valid merkle proofs

#### Phase C: Full Pool Contract

**Deliverables:**

- [ ] `GaleonPrivacyPool.sol` with ZK verification
- [ ] `MerkleTreeLib.sol` - Incremental merkle tree
- [ ] `PoseidonHasher.sol` - ZK-friendly hash
- [ ] Multi-ASP support
- [ ] Multi-denomination pools

#### Phase D: Relayer Network

**Deliverables:**

- [ ] Relayer smart contract
- [ ] Gas station network integration
- [ ] Relayer fee mechanism
- [ ] Frontend integration for gas-free withdrawals

---

## Frontend Components

### New Components Needed

| Component                 | Purpose                                  |
| ------------------------- | ---------------------------------------- |
| `PoolDepositModal.tsx`    | Deposit from Port to Pool                |
| `PoolWithdrawModal.tsx`   | Withdraw from Pool to Fog                |
| `PoolStatusCard.tsx`      | Show pool stats (deposits, your pending) |
| `PrivacyPoolProvider.tsx` | Context for pool state                   |

### User Flow: Port → Pool → Fog

```
┌─────────────────────────────────────────────────────────────────┐
│  /send page                                                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │  FUND YOUR FOG WALLETS                                      ││
│  │  ─────────────────────                                      ││
│  │                                                             ││
│  │  Choose how to fund:                                        ││
│  │                                                             ││
│  │  ┌──────────────────┐  ┌──────────────────┐                ││
│  │  │  FROM PORT       │  │  FROM POOL       │                ││
│  │  │  ────────────    │  │  ────────────    │                ││
│  │  │  Quick & simple  │  │  Maximum privacy │                ││
│  │  │                  │  │                  │                ││
│  │  │  • Use received  │  │  • ZK mixing     │                ││
│  │  │    payments      │  │  • No link to    │                ││
│  │  │  • Already clean │  │    any wallet    │                ││
│  │  │                  │  │  • 2-hour delay  │                ││
│  │  │  [Select Port]   │  │  [Use Pool]      │                ││
│  │  └──────────────────┘  └──────────────────┘                ││
│  └─────────────────────────────────────────────────────────────┘│
│                                                                  │
│  YOUR FOG WALLETS                                               │
│  ─────────────────                                              │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐            │
│  │ Fog #1       │ │ Fog #2       │ │ + New Wallet │            │
│  │ 1.5 MNT      │ │ Activating...│ │              │            │
│  │ Ready        │ │ 2hr left     │ │              │            │
│  └──────────────┘ └──────────────┘ └──────────────┘            │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Pool Deposit Flow

```
Step 1: Select Source Port
┌─────────────────────────────────────┐
│  Deposit to Privacy Pool            │
│  ─────────────────────              │
│                                     │
│  Select a Port with funds:          │
│                                     │
│  ○ Port #1 - 2.5 MNT               │
│  ● Port #3 - 1.2 MNT  ← Selected   │
│  ○ Port #5 - 0.8 MNT               │
│                                     │
│  Amount: 1 MNT (fixed)             │
│                                     │
│  [Continue]                         │
└─────────────────────────────────────┘

Step 2: Generate Commitment
┌─────────────────────────────────────┐
│  Generating your deposit...         │
│  ─────────────────────              │
│                                     │
│  ⏳ Creating secret...              │
│  ✅ Secret generated                │
│  ⏳ Creating commitment...          │
│  ✅ Commitment ready                │
│                                     │
│  ⚠️ SAVE THIS NOTE                  │
│  ┌─────────────────────────────┐   │
│  │ galeon-note:1:0x1234...     │   │
│  │                   [Copy]    │   │
│  └─────────────────────────────┘   │
│                                     │
│  You need this to withdraw later!  │
│                                     │
│  [I've saved it - Continue]        │
└─────────────────────────────────────┘

Step 3: Confirm Deposit
┌─────────────────────────────────────┐
│  Confirm Deposit                    │
│  ─────────────────────              │
│                                     │
│  From: Port #3                      │
│  Amount: 1 MNT                      │
│  Pool: Galeon Privacy Pool          │
│                                     │
│  ┌─────────────────────────────┐   │
│  │ After depositing, wait for  │   │
│  │ more users to deposit for   │   │
│  │ better anonymity set.       │   │
│  └─────────────────────────────┘   │
│                                     │
│  [Cancel]  [Deposit 1 MNT]         │
└─────────────────────────────────────┘
```

### Pool Withdrawal Flow

```
Step 1: Enter Note
┌─────────────────────────────────────┐
│  Withdraw from Privacy Pool         │
│  ─────────────────────              │
│                                     │
│  Paste your deposit note:           │
│  ┌─────────────────────────────┐   │
│  │ galeon-note:1:0x1234...     │   │
│  └─────────────────────────────┘   │
│                                     │
│  ✅ Valid note found                │
│  Deposited: 2 hours ago            │
│  Anonymity set: 47 deposits        │
│                                     │
│  [Continue]                         │
└─────────────────────────────────────┘

Step 2: Choose Destination
┌─────────────────────────────────────┐
│  Where to withdraw?                 │
│  ─────────────────────              │
│                                     │
│  ○ Existing Fog Wallet             │
│    └─ Fog #1 (0.5 MNT)             │
│                                     │
│  ● New Fog Wallet                  │
│    └─ Creates fresh stealth address│
│                                     │
│  [Continue]                         │
└─────────────────────────────────────┘

Step 3: Confirm Withdrawal (v0)
┌─────────────────────────────────────┐
│  Confirm Withdrawal                 │
│  ─────────────────────              │
│                                     │
│  Amount: 1 MNT                      │
│  To: New Fog Wallet                 │
│                                     │
│  ┌─────────────────────────────┐   │
│  │ 🛡️ Privacy Level: High       │   │
│  │ • Timelock mixing (2+ hours)│   │
│  │ • Link to Port broken       │   │
│  │ • Ready to pay privately    │   │
│  └─────────────────────────────┘   │
│                                     │
│  [Cancel]  [Withdraw]               │
└─────────────────────────────────────┘

Note: Full vision will add ZK proof generation step here.
```

---

## Data Types

### New Types in `types/fog.ts`

```typescript
// Privacy Pool types
export interface PoolDeposit {
  id: string
  commitment: `0x${string}`
  note: string // Encrypted note for user
  leafIndex: number
  depositedAt: number
  txHash: `0x${string}`
  sourcePortIndex?: number // If deposited from Port
  status: 'pending' | 'confirmed' | 'spent'
}

export interface PoolWithdrawal {
  id: string
  nullifierHash: `0x${string}`
  recipient: `0x${string}` // Direct to recipient - no intermediate address
  amount: string
  withdrawnAt: number
  txHash: `0x${string}`
  aspUsed: `0x${string}`
}

export interface PoolStats {
  totalDeposits: number
  totalWithdrawals: number
  pendingDeposits: number // Yours
  anonymitySet: number // Current unique deposits
  aspRoot: `0x${string}`
  lastUpdated: number
}

// Note format: galeon-note:VERSION:SECRET_HEX:NULLIFIER_HEX
export type PoolNote = `galeon-note:${number}:${string}:${string}`
```

---

## Security Considerations

### Threat Model

| Threat                | Mitigation                                       |
| --------------------- | ------------------------------------------------ |
| Double-spend          | Nullifier tracking on-chain                      |
| Fake proofs           | Groth16 ZK verification                          |
| Deposit front-running | Commitment hash hides secret                     |
| ASP censorship        | Multiple approved ASPs                           |
| ASP collusion         | ASP only sees deposit addresses, not withdrawals |
| Timing attacks        | 2hr auto-hop delay after withdrawal              |
| Amount correlation    | Fixed 1 MNT denomination                         |

### What Galeon ASP Knows

| Data                        | Visible?              |
| --------------------------- | --------------------- |
| Deposit address             | ✅ Yes                |
| Deposit amount              | ✅ Yes (always 1 MNT) |
| Deposit commitment          | ✅ Yes                |
| Withdrawal address          | ❌ No (only on-chain) |
| Which deposit was withdrawn | ❌ No (ZK proof)      |
| User identity               | ❌ No                 |

### What On-Chain Observers Know

| Data                              | Visible?                    |
| --------------------------------- | --------------------------- |
| Someone deposited                 | ✅ Yes                      |
| Someone withdrew                  | ✅ Yes                      |
| Link between deposit & withdrawal | ❌ No                       |
| Deposit from sanctioned address   | ✅ Yes (but can't withdraw) |

### v1 Remaining Limitations (0xbow Fork)

Even with the 0xbow fork providing ZK proofs, some limitations remain:

| Issue                              | Description                                                                                          | Mitigation                               | Future Improvement              |
| ---------------------------------- | ---------------------------------------------------------------------------------------------------- | ---------------------------------------- | ------------------------------- |
| **Gas payment for registration**   | `registerWithdrawalAddress()` must be called from some EOA that pays gas, creating linkable metadata | Call from Port address before depositing | Add relayer in v2               |
| **Stealth registration is public** | `WithdrawalAddressRegistered` events reveal which addresses are Galeon Fog wallets                   | Not a security issue, just metadata      | Relayer hides this              |
| **Note backup critical**           | If user loses localStorage, funds are stuck forever                                                  | Force backup confirmation, export option | Backend-encrypted backup option |
| **Centralized ban list**           | Owner-controlled ban list could be abused                                                            | Transparent on-chain, multi-sig owner    | DAO governance + multi-ASP      |
| **Port-only deposit restriction**  | Only Port addresses can deposit (by design)                                                          | Feature not bug - ensures covenant       | Optional external deposits v2   |
| **Single denomination**            | Fixed 1 MNT per deposit                                                                              | Multiple deposits for larger amounts     | Multi-denomination pools v2     |
| **Proof generation time**          | ZK proof takes 10-30s in browser                                                                     | Web worker, progress indicator           | WASM optimization, mobile       |

### v1 Gas Payment Flow

**Who pays gas for what:**

| Action                        | Who Calls            | Who Pays Gas     | Privacy Implication             |
| ----------------------------- | -------------------- | ---------------- | ------------------------------- |
| `deposit()`                   | Port stealth address | Port (has funds) | ✅ OK - Port already public     |
| `registerWithdrawalAddress()` | Port address         | Port (has funds) | ✅ OK - done before deposit     |
| `withdraw()`                  | Any EOA              | Caller           | ⚠️ Links gas payer to recipient |

**Recommended flow for maximum privacy:**

1. Generate Fog wallet address client-side
2. Call `registerWithdrawalAddress()` from the Port address (has funds)
3. Call `deposit()` from the Port address
4. Wait for anonymity set to grow
5. Generate ZK proof in browser
6. Call `withdraw()` from a fresh burner EOA (funded via CEX)

**v2 Improvement:** Relayer network will allow gas-free `registerWithdrawalAddress()` and `withdraw()` calls.

---

## Compliance with Privacy Pools Standard

### Full Compliance via 0xbow Fork

Galeon v1 achieves **full compliance** with the Privacy Pools standard by forking 0xbow:

| Feature                    | 0xbow Privacy Pools               | Galeon v1 (0xbow Fork)                    |
| -------------------------- | --------------------------------- | ----------------------------------------- |
| **Proof System**           | Groth16 ZK-SNARKs (BN254)         | ✅ Same (Groth16, BN254)                  |
| **Commitment Scheme**      | Poseidon hash                     | ✅ Same (Poseidon)                        |
| **Nullifiers**             | Required for ZK withdrawal        | ✅ Same (nullifier-based)                 |
| **Merkle Tree**            | Depth 20 (~1M deposits)           | ✅ Same                                   |
| **ASP Model**              | Proactive deposit approval        | ✅ Same + Galeon ban list                 |
| **Ragequit**               | Yes - public exit if not approved | ✅ Same (from 0xbow)                      |
| **Deposit Source**         | Any address                       | 🔒 Port addresses only (stricter)         |
| **Withdrawal Destination** | Any address                       | 🔒 Registered Fog wallets only (stricter) |
| **Multi-Asset**            | Native + ERC20                    | ⏳ Native only for v1, ERC20 in v2        |

### Galeon-Specific Modifications

**1. Port-Only Deposits (Stricter than 0xbow)**

0xbow allows any address to deposit, relying on ASP to filter bad actors post-deposit. Galeon adds an additional layer:

```
0xbow:   Anyone → Pool → ASP filters → Withdrawal
Galeon:  Port only → Pool → ASP + Ban list → Fog wallet (stealth-only)
```

This means all deposits are from covenant signers - "clean by design."

**2. Stealth-Only Withdrawals (Stricter than 0xbow)**

0xbow allows withdrawal to any address. Galeon requires registration of Fog wallet addresses with ephemeral key validation, ensuring:

- Withdrawals go to proper stealth addresses
- On-chain audit trail for compliance
- No accidental withdrawal to traceable addresses

### v1 Compliance Status (0xbow Fork)

| Standard Feature         | Status | Notes                        |
| ------------------------ | ------ | ---------------------------- |
| Groth16 ZK proofs        | ✅ v1  | From 0xbow fork              |
| Poseidon commitments     | ✅ v1  | From 0xbow fork              |
| Nullifier tracking       | ✅ v1  | From 0xbow fork              |
| Merkle tree membership   | ✅ v1  | From 0xbow fork              |
| Ragequit mechanism       | ✅ v1  | From 0xbow fork              |
| ASP system               | ✅ v1  | From 0xbow + Galeon ban list |
| Port-only deposits       | ✅ v1  | Galeon addition (stricter)   |
| Stealth-only withdrawals | ✅ v1  | Galeon addition (stricter)   |
| Multi-ASP support        | ⏳ v2  | Planned for future           |
| Relayer network          | ⏳ v2  | Gas-free withdrawals         |
| Multi-denomination       | ⏳ v2  | 0.1, 1, 10 MNT pools         |
| ERC20 tokens             | ⏳ v2  | USDC, USDT support           |

### References

- [0xbow Privacy Pools](https://github.com/0xbow/privacy-pools) - Fork source (launched March 2025)
- [Privacy Pools Documentation](https://docs.privacypools.com/) - Official protocol docs
- [Privacy Pools Paper](https://papers.ssrn.com/sol3/papers.cfm?abstract_id=4563364) - Vitalik Buterin et al.
- [snarkjs](https://github.com/iden3/snarkjs) - ZK proof library
- [Circom](https://docs.circom.io/) - Circuit language

---

## Compliance Enforcement System

### Why `commitmentDepositor` is Required

The Pool must track which stealth address deposited each commitment. This gives Galeon **freeze authority** without **surveillance capability**.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    WHAT commitmentDepositor ENABLES                      │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  WITHOUT commitmentDepositor:                                            │
│  ┌────────────────────────────────────────────────────────────────┐     │
│  │ Bad actor deposits → we don't know which commitment            │     │
│  │ → Cannot add to exclusion set                                  │     │
│  │ → Cannot freeze their funds                                    │     │
│  │ → They withdraw freely                                         │     │
│  └────────────────────────────────────────────────────────────────┘     │
│                                                                          │
│  WITH commitmentDepositor:                                               │
│  ┌────────────────────────────────────────────────────────────────┐     │
│  │ Bad actor deposits → we know their commitment                  │     │
│  │ → Add commitment to exclusion set                              │     │
│  │ → Their proof fails (can't prove NOT in exclusion)             │     │
│  │ → Funds frozen                                                 │     │
│  │                                                                │     │
│  │ But: We still don't know where good actors withdraw to         │     │
│  └────────────────────────────────────────────────────────────────┘     │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### Why This Doesn't Reduce ZK Privacy

The ZK proof structure preserves privacy even with `commitmentDepositor`:

```
Deposit:
  commitment = hash(nullifier, secret)
  → commitment is PUBLIC (stored in tree)
  → nullifier + secret are PRIVATE (only user knows)

Withdraw:
  User proves: "I know (nullifier, secret) such that hash(nullifier, secret) is in the tree"
  → Reveals: nullifierHash (to prevent double-spend)
  → Does NOT reveal: which commitment, or the secret
```

**The missing link for tracing:**

| Galeon Knows                     | Galeon Doesn't Know                   |
| -------------------------------- | ------------------------------------- |
| Commitment X belongs to User A   | The nullifier for commitment X        |
| User B withdrew with nullifier N | Which commitment produced nullifier N |

Without the `secret`, we cannot compute: `commitment → nullifier`. So even with `commitmentDepositor`:

- "User A deposited commitment X" ✅
- "Someone withdrew using nullifier N" ✅
- **Cannot prove:** "User A made this withdrawal" ❌

**Summary:**

> `commitmentDepositor` = **freeze authority** without **surveillance capability**
>
> ZK protects the deposit → withdrawal link. These are orthogonal.

---

### Amount-Limited Deposits (Dusting Attack Prevention)

**Problem:** Bad actor could send dirty funds directly to a valid Port stealth address, then the Port owner unknowingly deposits "dirty" funds to the Pool.

**Solution:** Only allow deposits up to the amount verified through GaleonRegistry.

```solidity
// Track verified amounts per stealth address (from GaleonRegistry payments)
mapping(address => uint256) public verifiedBalance;

// Called by GaleonRegistry after payment
function recordVerifiedPayment(address stealthAddress, uint256 amount) external {
    require(msg.sender == address(galeonRegistry), "Only registry");
    verifiedBalance[stealthAddress] += amount;
}

function deposit(bytes32 commitment) external payable {
    require(msg.value > 0, "Zero deposit");
    require(verifiedBalance[msg.sender] >= msg.value, "Exceeds verified balance");

    // Deduct from verified balance (prevents double-deposit)
    verifiedBalance[msg.sender] -= msg.value;

    // Track depositor for compliance
    commitmentDepositor[commitment] = msg.sender;
    commitmentAmount[commitment] = msg.value;

    // ... rest of deposit logic
}
```

This ensures:

1. Only funds that came through GaleonRegistry can enter the Pool
2. Direct sends to stealth addresses cannot be deposited
3. Dusting attacks are ineffective

---

### Bad Actor Handling by Stage

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    BAD ACTOR TIMELINE                                    │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  STAGE 1: Port Active (Before Pool)                                     │
│  ┌────────────────────────────────────────────────────────────────┐     │
│  │ Bad actor receives payments to Port                            │     │
│  │                                                                │     │
│  │ Galeon CAN:                                                    │     │
│  │ ✅ See all payments (viewing key)                              │     │
│  │ ✅ Generate reports                                            │     │
│  │ ✅ Add to ASP blocklist                                        │     │
│  │ ✅ Block future Pool deposits                                  │     │
│  │                                                                │     │
│  │ Galeon CANNOT:                                                 │     │
│  │ ❌ Freeze funds in their stealth address (no spending key)     │     │
│  │ ❌ Reverse payments                                            │     │
│  └────────────────────────────────────────────────────────────────┘     │
│                                                                          │
│  STAGE 2: Deposited to Pool (Before Withdrawal)                         │
│  ┌────────────────────────────────────────────────────────────────┐     │
│  │ Bad actor has commitment in Merkle tree                        │     │
│  │                                                                │     │
│  │ Galeon CAN:                                                    │     │
│  │ ✅ Know which commitment belongs to them (commitmentDepositor) │     │
│  │ ✅ Add commitment to ASP exclusion set                         │     │
│  │ ✅ FREEZE their withdrawal (proof will fail exclusion check)   │     │
│  │                                                                │     │
│  │ Galeon CANNOT:                                                 │     │
│  │ ❌ Seize funds directly (no admin withdrawal function)         │     │
│  │ ❌ Know if they attempt to withdraw (anonymous attempts)       │     │
│  └────────────────────────────────────────────────────────────────┘     │
│                                                                          │
│  STAGE 3: Already Withdrawn                                              │
│  ┌────────────────────────────────────────────────────────────────┐     │
│  │ Bad actor withdrew with valid ZK proof                         │     │
│  │                                                                │     │
│  │ Galeon CAN:                                                    │     │
│  │ ✅ Prove they deposited X amount on date Y (on-chain record)   │     │
│  │ ✅ Provide pre-Pool transaction history                        │     │
│  │ ✅ Sanction their Port (block future activity)                 │     │
│  │                                                                │     │
│  │ Galeon CANNOT:                                                 │     │
│  │ ❌ Know where funds went (ZK privacy)                          │     │
│  │ ❌ Reverse the withdrawal                                      │     │
│  │ ❌ Link withdrawal address to deposit                          │     │
│  └────────────────────────────────────────────────────────────────┘     │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

**Key Insight:** The Pool is the "privacy firewall":

- **Before Pool**: Full traceability (viewing keys)
- **After Pool**: No traceability (ZK)

---

### Frozen Fund Recovery System

Frozen funds shouldn't be wasted. The system provides appeal + treasury recovery:

```solidity
// Exclusion with metadata
struct Exclusion {
    bool excluded;
    uint256 excludedAt;
    uint256 amount;
    address depositor;
}

mapping(bytes32 => Exclusion) public exclusions;
mapping(bytes32 => bool) public frozenClaimed;

uint256 public constant APPEAL_PERIOD = 30 days;
address public treasury;

// ASP excludes a commitment (freeze)
function excludeCommitment(bytes32 commitment) external onlyASP {
    require(commitmentDepositor[commitment] != address(0), "Unknown commitment");

    exclusions[commitment] = Exclusion({
        excluded: true,
        excludedAt: block.timestamp,
        amount: commitmentAmount[commitment],
        depositor: commitmentDepositor[commitment]
    });

    emit CommitmentExcluded(commitment, commitmentDepositor[commitment]);
}

// ASP removes exclusion (appeal successful)
function removeExclusion(bytes32 commitment) external onlyASP {
    require(exclusions[commitment].excluded, "Not excluded");

    exclusions[commitment].excluded = false;
    emit ExclusionRemoved(commitment);
    // User can now withdraw normally
}

// ASP claims frozen funds after appeal period
function claimFrozenFunds(bytes32 commitment) external onlyASP {
    Exclusion memory exc = exclusions[commitment];

    require(exc.excluded, "Not excluded");
    require(block.timestamp >= exc.excludedAt + APPEAL_PERIOD, "Appeal period active");
    require(!frozenClaimed[commitment], "Already claimed");

    frozenClaimed[commitment] = true;

    (bool success, ) = treasury.call{value: exc.amount}("");
    require(success, "Transfer failed");

    emit FrozenFundsClaimed(commitment, exc.amount);
}
```

**Recovery Flow:**

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    EXCLUSION + RECOVERY FLOW                             │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  Day 0: Bad actor discovered                                            │
│         → ASP calls excludeCommitment(0xCOMM)                           │
│         → User cannot withdraw (proof fails)                            │
│         → Appeal period starts (30 days)                                │
│                                                                          │
│  Day 1-30: Appeal Window                                                │
│         → User can contact Galeon to appeal                             │
│         → If valid: ASP calls removeExclusion(0xCOMM)                   │
│         → User withdraws normally                                       │
│                                                                          │
│  Day 31+: Claim Window                                                  │
│         → If no appeal or appeal rejected                               │
│         → ASP calls claimFrozenFunds(0xCOMM)                            │
│         → Funds go to treasury                                          │
│                                                                          │
│  Treasury Options:                                                       │
│         → Hold for potential legal claims                               │
│         → Redistribute to pool users                                    │
│         → Burn (deflationary)                                           │
│         → Donate to charity                                             │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

---

### Sanction Effectiveness Summary

| When Discovered                | Funds Recoverable | Funds Frozen           | Trail Available |
| ------------------------------ | ----------------- | ---------------------- | --------------- |
| Before deposit                 | N/A (blocked)     | N/A                    | ✅ Full         |
| After deposit, before withdraw | ❌ No (to user)   | ✅ Yes (ASP exclusion) | ✅ Full to Pool |
| After withdraw                 | ❌ No             | ❌ No                  | ✅ To Pool only |

---

### Future: KYC for Post-Withdraw Accountability

For maximum compliance (v2+), KYC can be added at covenant signing:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    COMPLIANCE TIERS                                      │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  TIER 1: Current (Hackathon)                                            │
│  ┌────────────────────────────────────────────────────────────────┐     │
│  │ • Wallet signature (pseudonymous)                              │     │
│  │ • Covenant signing (legal agreement)                           │     │
│  │ • Viewing key escrow (traceable to Port)                       │     │
│  │                                                                │     │
│  │ Post-withdraw: Know Port identity, not real identity           │     │
│  └────────────────────────────────────────────────────────────────┘     │
│                                                                          │
│  TIER 2: Future (KYC)                                                   │
│  ┌────────────────────────────────────────────────────────────────┐     │
│  │ • Everything from Tier 1                                       │     │
│  │ • KYC at covenant signing (real identity verified)             │     │
│  │                                                                │     │
│  │ Post-withdraw: Know real-world identity                        │     │
│  │ → Can report to authorities with name/ID                       │     │
│  │ → Full legal recourse even after ZK withdrawal                 │     │
│  └────────────────────────────────────────────────────────────────┘     │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

**Trade-off:**

- No KYC → More users, less friction, but post-withdraw is "wallet address only"
- KYC → Fewer users, more friction, but full legal recourse post-withdraw

For hackathon: Tier 1 is sufficient. KYC can be added for institutional/regulated use cases in v2.

---

## Testing Checklist

### Unit Tests

**Core Pool:**

- [ ] Deposit with valid commitment succeeds
- [ ] Deposit with wrong amount fails
- [ ] Deposit with zero commitment fails
- [ ] Withdrawal with valid proof succeeds
- [ ] Withdrawal with invalid proof fails
- [ ] Withdrawal with used nullifier fails
- [ ] ASP root update by approved ASP succeeds
- [ ] ASP root update by non-ASP fails
- [ ] Owner can approve/revoke ASP

**Compliance - Port-Only Deposits:**

- [ ] Deposit from Port address succeeds
- [ ] Deposit from non-Port address fails
- [ ] Deposit exceeding verified balance fails
- [ ] Verified balance updates correctly after payment
- [ ] Multiple payments accumulate verified balance

**Compliance - commitmentDepositor:**

- [ ] commitmentDepositor tracked correctly on deposit
- [ ] commitmentAmount tracked correctly on deposit
- [ ] Can query depositor for any commitment

**Compliance - Exclusion System:**

- [ ] ASP can exclude commitment
- [ ] Non-ASP cannot exclude commitment
- [ ] Excluded commitment cannot withdraw (proof fails)
- [ ] ASP can remove exclusion (appeal)
- [ ] User can withdraw after exclusion removed

**Compliance - Frozen Fund Recovery:**

- [ ] Cannot claim frozen funds during appeal period
- [ ] Can claim frozen funds after appeal period
- [ ] Claimed funds go to treasury
- [ ] Cannot claim same commitment twice
- [ ] Treasury address can be updated by owner

**Stealth Withdrawals:**

- [ ] Registration with valid ephemeral key succeeds
- [ ] Registration with invalid key length fails
- [ ] Registration with invalid prefix fails
- [ ] Withdrawal to registered address succeeds
- [ ] Withdrawal to unregistered address fails

### Integration Tests

- [ ] Full deposit → withdraw flow
- [ ] Deposit from Port with verified balance
- [ ] Withdraw to registered Fog wallet
- [ ] Multiple deposits before withdrawal
- [ ] Withdraw with different ASPs
- [ ] Gas cost within limits
- [ ] Exclusion → appeal → withdrawal flow
- [ ] Exclusion → claim frozen funds flow
- [ ] GaleonRegistry → Pool verified balance sync

### E2E Tests

- [ ] User deposits from Port UI
- [ ] User saves note successfully
- [ ] User withdraws with note
- [ ] New Fog wallet created from withdrawal
- [ ] Auto-hop triggers after withdrawal
- [ ] Full flow: Port → Pool → Fog → Pay
- [ ] Bad actor freeze scenario
- [ ] Appeal and unfreeze scenario
- [ ] Treasury claim after appeal period

---

## Gas Estimates

| Operation       | Estimated Gas | Cost @ 0.02 gwei |
| --------------- | ------------- | ---------------- |
| Deposit         | ~200,000      | ~0.004 MNT       |
| Withdrawal      | ~800,000      | ~0.016 MNT       |
| ASP Root Update | ~50,000       | ~0.001 MNT       |

---

## Contract Upgradeability

### Why Upgradeable Contracts

| Reason                 | Explanation                                                   |
| ---------------------- | ------------------------------------------------------------- |
| **Privacy Pools v2**   | 0xbow launching shielded pools March 2026 - need to integrate |
| **Bug fixes**          | ZK circuits and compliance logic may need updates             |
| **Feature additions**  | KYC, multi-denomination, ERC20, relayers                      |
| **Compliance updates** | Regulations will evolve                                       |

### Upgrade Pattern: UUPS

All core contracts should use OpenZeppelin's UUPS (Universal Upgradeable Proxy Standard):

```solidity
// Example: GaleonRegistryV1.sol
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";

contract GaleonRegistryV1 is
    UUPSUpgradeable,
    OwnableUpgradeable,
    ReentrancyGuardUpgradeable
{
    // Replace immutables with regular state
    IERC5564Announcer public announcer;
    IERC6538Registry public registry;

    // Storage gap for future upgrades (50 slots)
    uint256[50] private __gap;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(
        address _announcer,
        address _registry,
        address _owner
    ) public initializer {
        __UUPSUpgradeable_init();
        __Ownable_init(_owner);
        __ReentrancyGuard_init();

        announcer = IERC5564Announcer(_announcer);
        registry = IERC6538Registry(_registry);
    }

    function _authorizeUpgrade(address newImplementation)
        internal
        override
        onlyOwner
    {}
}
```

### Contracts to Make Upgradeable

| Contract                   | Priority | Migration Notes                                         |
| -------------------------- | -------- | ------------------------------------------------------- |
| **GaleonRegistry**         | High     | Replace `immutable` with state vars, add `initialize()` |
| **GaleonPrivacyPool**      | High     | ZK verifier can be upgraded separately                  |
| **GaleonCovenantRegistry** | Medium   | Future KYC integration                                  |

### Storage Layout Rules

1. **Never remove or reorder existing storage variables**
2. **Always add new variables at the end**
3. **Use storage gaps (`uint256[50] private __gap`) for future additions**
4. **Document storage layout in comments**

### Upgrade Governance

For hackathon: Owner-controlled upgrades (simple)
For production: Consider timelocks or multisig:

```solidity
// Future: TimelockController for upgrades
ITimelockController public upgradeTimelock;
uint256 public constant UPGRADE_DELAY = 2 days;

function _authorizeUpgrade(address newImplementation) internal override {
    require(
        upgradeTimelock.isOperationReady(keccak256(abi.encode(newImplementation))),
        "Upgrade not scheduled or not ready"
    );
}
```

---

## Dependencies

### Smart Contracts

```json
{
  "@openzeppelin/contracts": "^5.0.0",
  "@openzeppelin/contracts-upgradeable": "^5.0.0",
  "circomlibjs": "^0.1.7",
  "snarkjs": "^0.7.0"
}
```

### ZK Tools

- `circom` 2.1.x - Circuit compiler
- `snarkjs` 0.7.x - Proof generation/verification
- `circomlib` - Standard circuit libraries

### Frontend

```json
{
  "snarkjs": "^0.7.0",
  "ffjavascript": "^0.2.60"
}
```

---

## Timeline (v1 - 0xbow Fork)

| Phase     | Duration     | Cumulative | Deliverables                              |
| --------- | ------------ | ---------- | ----------------------------------------- |
| 1         | 3-4 days     | Day 4      | Fork contracts, add Galeon modifications  |
| 2         | 2-3 days     | Day 7      | ZK circuits, browser proof generation     |
| 3         | 2-3 days     | Day 10     | Frontend integration, deposit/withdraw UI |
| 4         | 1 day        | Day 11     | Note management, encrypted storage        |
| 5         | 2 days       | Day 13     | Testing, deploy to Mantle Sepolia         |
| **Total** | **~2 weeks** |            |                                           |

---

## Open Questions (Mostly Resolved)

1. ~~**Denomination**: Fixed 1 MNT or multiple tiers (0.1, 1, 10)?~~ → Fixed 1 MNT for v1
2. ~~**Relayer**: Add relayer for gas-free withdrawals?~~ → Deferred to v2
3. ~~**Multiple pools**: One pool or separate by denomination?~~ → Single pool for v1
4. ~~**Note storage**: LocalStorage vs backend vs user responsibility?~~ → Encrypted localStorage
5. ~~**ASP decentralization**: Start with Galeon-only or add others?~~ → Galeon-only for v1
6. ~~**ZK vs Commit-Reveal**: Use ZK proofs or simpler approach?~~ → ZK (0xbow fork)

---

## References

- [0xbow Privacy Pools](https://github.com/0xbow/privacy-pools) - Fork source
- [Privacy Pools Paper](https://papers.ssrn.com/sol3/papers.cfm?abstract_id=4563364) - Vitalik et al.
- [0xbow Documentation](https://docs.privacypools.com/) - Official docs
- [snarkjs](https://github.com/iden3/snarkjs) - ZK proof library
- [Circom](https://docs.circom.io/) - Circuit language
- [Tornado Cash](https://github.com/tornadocash/tornado-core) - Original implementation
- [Poseidon Hash](https://www.poseidon-hash.info/) - ZK-friendly hash
