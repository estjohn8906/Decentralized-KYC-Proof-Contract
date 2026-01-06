# 🔐 Decentralized KYC Proof Contract

🚀 A zero-knowledge proof-based KYC verification system built on Stacks blockchain using Clarity smart contracts.

## 📋 Overview

This smart contract enables decentralized Know Your Customer (KYC) verification using zero-knowledge proofs, allowing users to prove their identity verification status without revealing sensitive personal information. The system supports multiple verification tiers and authorized verifiers.

## ✨ Features

- 🔒 **Zero-Knowledge Proofs**: Verify KYC status without exposing personal data
- 🎯 **Multi-Tier Verification**: Support for different verification levels (1-3)
- 👥 **Authorized Verifiers**: Decentralized network of trusted verifiers
- ⏰ **Time-Bound Proofs**: Automatic expiration for security
- 💰 **Fee Management**: Configurable verification fees
- 📊 **Reputation System**: Track verifier performance and reliability
- 🔄 **Proof Challenges**: Cryptographic challenges for secure submission

## 🏗️ Architecture

### Core Components

1. **KYC Proofs**: Store user verification data with proof hashes
2. **Verifier Registry**: Manage authorized verifiers and their reputation
3. **Proof Challenges**: Generate secure challenges for proof submission
4. **Verification History**: Immutable audit trail of all verifications

### Verification Tiers

- **Tier 1**: Basic verification
- **Tier 2**: Standard verification  
- **Tier 3**: Premium verification

## 🚀 Getting Started

### Prerequisites

- [Clarinet](https://github.com/hirosystems/clarinet) installed
- Stacks wallet for testing
- Basic understanding of Clarity smart contracts

### Installation

1. Clone the repository:
```bash
git clone <your-repo-url>
cd Decentralized-KYC-Proof-Contract
```

2. Install dependencies:
```bash
npm install
```

3. Run tests:
```bash
clarinet test
```

## 📖 Usage

### For Users

#### 1. Generate Proof Challenge 🎲
```clarity
(contract-call? .decentralized-kyc-proof-contract generate-proof-challenge)
```

#### 2. Submit KYC Proof 📤
```clarity
(contract-call? .decentralized-kyc-proof-contract submit-kyc-proof 
    proof-data 
    verification-tier 
    proof-solution)
```

#### 3. Check KYC Status 📊
```clarity
(contract-call? .decentralized-kyc-proof-contract get-kyc-status user-principal)
```

#### 4. Pay Verification Fee 💳
```clarity
(contract-call? .decentralized-kyc-proof-contract pay-verification-fee)
```

### For Verifiers

#### 1. Register as Verifier 👨‍💼
```clarity
(contract-call? .decentralized-kyc-proof-contract register-verifier)
```

#### 2. Verify User Proof ✅
```clarity
(contract-call? .decentralized-kyc-proof-contract verify-kyc-proof 
    user-principal 
    proof-hash 
    verification-tier)
```

#### 3. Revoke Verification ❌
```clarity
(contract-call? .decentralized-kyc-proof-contract revoke-kyc-proof user-principal)
```

### For Contract Owner

#### 1. Authorize Verifier 🔑
```clarity
(contract-call? .decentralized-kyc-proof-contract authorize-verifier verifier-principal)
```

#### 2. Update Verification Fee 💰
```clarity
(contract-call? .decentralized-kyc-proof-contract update-verification-fee new-fee)
```

#### 3. Revoke Verifier Access 🚫
```clarity
(contract-call? .decentralized-kyc-proof-contract revoke-verifier verifier-principal)
```

## 🔍 Read-Only Functions

### Check Verification Status
- `is-kyc-verified(user)` - Returns boolean verification status
- `get-verification-tier(user)` - Returns user's verification tier
- `get-kyc-status(user)` - Returns detailed verification info

### Verifier Information
- `get-verifier-info(verifier)` - Returns verifier details and reputation
- `get-verification-history(nonce)` - Returns specific verification record

### Contract Information
- `get-contract-info()` - Returns contract metadata
- `get-verification-fee()` - Returns current verification fee
- `verify-proof-hash(user, proof-hash)` - Validates proof hash

## 🔒 Security Features

- **Time-bound proofs**: All verifications expire after ~1 year (52,560 blocks)
- **Challenge-response**: Cryptographic challenges prevent replay attacks  
- **Authorization checks**: Only authorized verifiers can verify proofs
- **Reputation system**: Track verifier performance and trustworthiness
- **Proof hashing**: Secure SHA-256 hashing of proof data

## 🌐 Zero-Knowledge Integration

The contract implements ZK-proof concepts through:

1. **Proof Challenges**: Generate unique cryptographic challenges
2. **Proof Solutions**: Users provide solutions without revealing identity data
3. **Hash Verification**: Verify proofs through cryptographic hashes
4. **Data Separation**: Store proof hashes, not actual identity information

## 📊 Error Codes

| Code | Description |
|------|-------------|
| 100  | Owner only operation |
| 101  | Resource not found |
| 102  | Already verified |
| 103  | Invalid proof |
| 104  | Expired proof |
| 105  | Unauthorized access |
| 106  | Invalid verification tier |

## 🧪 Testing

Run the test suite:
```bash
clarinet test
```

Test specific functions:
```bash
clarinet console
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License.

## 🙋‍♂️ Support

For questions and support:
- Create an issue on GitHub
- Join our Discord community
- Check the documentation

---

Made with ❤️ for the decentralized future 🌍
