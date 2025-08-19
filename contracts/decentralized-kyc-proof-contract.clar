(define-constant contract-owner tx-sender)
(define-constant err-owner-only (err u100))
(define-constant err-not-found (err u101))
(define-constant err-already-verified (err u102))
(define-constant err-invalid-proof (err u103))
(define-constant err-expired-proof (err u104))
(define-constant err-unauthorized (err u105))
(define-constant err-invalid-tier (err u106))

(define-data-var proof-nonce uint u0)
(define-data-var verification-fee uint u1000000)

(define-map kyc-proofs principal {
    proof-hash: (buff 32),
    verification-tier: uint,
    verified-at: uint,
    expires-at: uint,
    proof-data: (buff 256),
    verifier: principal,
    status: uint
})

(define-map verifier-registry principal {
    is-authorized: bool,
    verification-count: uint,
    reputation-score: uint,
    registered-at: uint
})

(define-map proof-challenges principal {
    challenge-hash: (buff 32),
    created-at: uint,
    expires-at: uint,
    solved: bool
})

(define-map verification-history uint {
    user: principal,
    verifier: principal,
    proof-hash: (buff 32),
    verification-tier: uint,
    timestamp: uint
})

(define-public (register-verifier)
    (begin
        (asserts! (is-eq tx-sender contract-owner) err-owner-only)
        (ok (map-set verifier-registry tx-sender {
            is-authorized: true,
            verification-count: u0,
            reputation-score: u100,
            registered-at: stacks-block-height
        }))
    )
)

(define-public (authorize-verifier (verifier principal))
    (begin
        (asserts! (is-eq tx-sender contract-owner) err-owner-only)
        (ok (map-set verifier-registry verifier {
            is-authorized: true,
            verification-count: u0,
            reputation-score: u100,
            registered-at: stacks-block-height
        }))
    )
)

(define-public (revoke-verifier (verifier principal))
    (begin
        (asserts! (is-eq tx-sender contract-owner) err-owner-only)
        (match (map-get? verifier-registry verifier)
            verifier-data (ok (map-set verifier-registry verifier 
                (merge verifier-data { is-authorized: false })))
            err-not-found
        )
    )
)

(define-public (generate-proof-challenge)
    (let
        (
            (challenge-hash (sha256 (concat (unwrap-panic (to-consensus-buff? tx-sender)) 
                                          (unwrap-panic (to-consensus-buff? stacks-block-height)))))
            (expires-at (+ stacks-block-height u144))
        )
        (map-set proof-challenges tx-sender {
            challenge-hash: challenge-hash,
            created-at: stacks-block-height,
            expires-at: expires-at,
            solved: false
        })
        (ok challenge-hash)
    )
)

(define-public (submit-kyc-proof 
    (proof-data (buff 256)) 
    (verification-tier uint)
    (proof-solution (buff 32)))
    (let
        (
            (challenge-data (unwrap! (map-get? proof-challenges tx-sender) err-not-found))
            (proof-hash (sha256 (concat proof-data proof-solution)))
            (expires-at (+ stacks-block-height u52560))
            (current-nonce (+ (var-get proof-nonce) u1))
        )
        (asserts! (< stacks-block-height (get expires-at challenge-data)) err-expired-proof)
        (asserts! (not (get solved challenge-data)) err-invalid-proof)
        (asserts! (<= verification-tier u3) err-invalid-tier)
        
        (var-set proof-nonce current-nonce)
        
        (map-set proof-challenges tx-sender 
            (merge challenge-data { solved: true }))
        
        (map-set kyc-proofs tx-sender {
            proof-hash: proof-hash,
            verification-tier: verification-tier,
            verified-at: stacks-block-height,
            expires-at: expires-at,
            proof-data: proof-data,
            verifier: contract-owner,
            status: u1
        })
        
        (map-set verification-history current-nonce {
            user: tx-sender,
            verifier: contract-owner,
            proof-hash: proof-hash,
            verification-tier: verification-tier,
            timestamp: stacks-block-height
        })
        
        (ok proof-hash)
    )
)

(define-public (verify-kyc-proof 
    (user principal) 
    (proof-hash (buff 32))
    (verification-tier uint))
    (let
        (
            (verifier-data (unwrap! (map-get? verifier-registry tx-sender) err-unauthorized))
            (user-proof (unwrap! (map-get? kyc-proofs user) err-not-found))
            (expires-at (+ stacks-block-height u52560))
            (current-nonce (+ (var-get proof-nonce) u1))
        )
        (asserts! (get is-authorized verifier-data) err-unauthorized)
        (asserts! (is-eq (get proof-hash user-proof) proof-hash) err-invalid-proof)
        (asserts! (< stacks-block-height (get expires-at user-proof)) err-expired-proof)
        (asserts! (<= verification-tier u3) err-invalid-tier)
        
        (var-set proof-nonce current-nonce)
        
        (map-set kyc-proofs user 
            (merge user-proof { 
                verification-tier: verification-tier,
                verifier: tx-sender,
                verified-at: stacks-block-height,
                expires-at: expires-at,
                status: u2
            }))
        
        (map-set verifier-registry tx-sender
            (merge verifier-data { 
                verification-count: (+ (get verification-count verifier-data) u1),
                reputation-score: (+ (get reputation-score verifier-data) u10)
            }))
        
        (map-set verification-history current-nonce {
            user: user,
            verifier: tx-sender,
            proof-hash: proof-hash,
            verification-tier: verification-tier,
            timestamp: stacks-block-height
        })
        
        (ok true)
    )
)

(define-public (revoke-kyc-proof (user principal))
    (let
        (
            (user-proof (unwrap! (map-get? kyc-proofs user) err-not-found))
            (verifier-data (unwrap! (map-get? verifier-registry tx-sender) err-unauthorized))
        )
        (asserts! (get is-authorized verifier-data) err-unauthorized)
        (asserts! (or (is-eq tx-sender (get verifier user-proof)) 
                     (is-eq tx-sender contract-owner)) err-unauthorized)
        
        (map-set kyc-proofs user 
            (merge user-proof { status: u0, expires-at: stacks-block-height }))
        
        (ok true)
    )
)

(define-public (update-verification-fee (new-fee uint))
    (begin
        (asserts! (is-eq tx-sender contract-owner) err-owner-only)
        (ok (var-set verification-fee new-fee))
    )
)

(define-public (pay-verification-fee)
    (let
        (
            (fee-amount (var-get verification-fee))
        )
        (try! (stx-transfer? fee-amount tx-sender contract-owner))
        (ok fee-amount)
    )
)

(define-read-only (get-kyc-status (user principal))
    (match (map-get? kyc-proofs user)
        user-proof (ok {
            verified: (> (get status user-proof) u0),
            verification-tier: (get verification-tier user-proof),
            verified-at: (get verified-at user-proof),
            expires-at: (get expires-at user-proof),
            verifier: (get verifier user-proof),
            is-expired: (>= stacks-block-height (get expires-at user-proof))
        })
        (ok {
            verified: false,
            verification-tier: u0,
            verified-at: u0,
            expires-at: u0,
            verifier: contract-owner,
            is-expired: true
        })
    )
)

(define-read-only (get-proof-challenge (user principal))
    (map-get? proof-challenges user)
)

(define-read-only (get-verifier-info (verifier principal))
    (map-get? verifier-registry verifier)
)

(define-read-only (get-verification-history (nonce uint))
    (map-get? verification-history nonce)
)

(define-read-only (get-verification-fee)
    (var-get verification-fee)
)

(define-read-only (is-kyc-verified (user principal))
    (match (map-get? kyc-proofs user)
        user-proof (and 
            (> (get status user-proof) u0)
            (< stacks-block-height (get expires-at user-proof)))
        false
    )
)

(define-read-only (get-verification-tier (user principal))
    (match (map-get? kyc-proofs user)
        user-proof (if (and 
                        (> (get status user-proof) u0)
                        (< stacks-block-height (get expires-at user-proof)))
                      (get verification-tier user-proof)
                      u0)
        u0
    )
)

(define-read-only (verify-proof-hash (user principal) (proof-hash (buff 32)))
    (match (map-get? kyc-proofs user)
        user-proof (is-eq (get proof-hash user-proof) proof-hash)
        false
    )
)

(define-read-only (get-contract-info)
    (ok {
        owner: contract-owner,
        total-verifications: (var-get proof-nonce),
        verification-fee: (var-get verification-fee),
        contract-version: u1
    })
)
