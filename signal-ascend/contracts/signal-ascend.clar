;; Signal-Ascend Privacy-Preserving Reputation Protocol
;; A simplified implementation for Stacks blockchain

;; Constants
(define-constant CONTRACT_OWNER tx-sender)
(define-constant ERR_UNAUTHORIZED (err u100))
(define-constant ERR_USER_NOT_FOUND (err u101))
(define-constant ERR_INVALID_SCORE (err u102))
(define-constant ERR_INSUFFICIENT_STAKE (err u103))
(define-constant ERR_PROOF_VERIFICATION_FAILED (err u104))

;; Minimum stake required for reputation attestation (in microSTX)
(define-constant MIN_STAKE_AMOUNT u1000000) ;; 1 STX

;; Data Variables
(define-data-var next-user-id uint u1)

;; Data Maps
;; User credibility profiles
(define-map user-profiles
  principal
  {
    user-id: uint,
    reputation-score: uint,
    stake-amount: uint,
    last-updated: uint,
    verification-count: uint,
    is-verified: bool
  }
)

;; Credibility attestations from verifiers
(define-map attestations
  { attester: principal, target: principal }
  {
    score: uint,
    timestamp: uint,
    domain: (string-ascii 50),
    proof-hash: (buff 32)
  }
)

;; Verifier registry for credibility oracles
(define-map verifiers
  principal
  {
    is-active: bool,
    stake-amount: uint,
    attestation-count: uint,
    reputation: uint
  }
)

;; Cross-chain credibility proofs
(define-map credibility-proofs
  (buff 32)
  {
    user: principal,
    score-threshold: uint,
    expiry-height: uint,
    is-valid: bool
  }
)

;; Reputation domains for different use cases
(define-map reputation-domains
  (string-ascii 50)
  {
    min-score: uint,
    decay-rate: uint,
    is-active: bool
  }
)

;; Read-only functions

;; Get user profile
(define-read-only (get-user-profile (user principal))
  (map-get? user-profiles user)
)

;; Get user reputation score with temporal decay
(define-read-only (get-current-reputation (user principal))
  (match (map-get? user-profiles user)
    profile
    (let
      (
        (base-score (get reputation-score profile))
        (last-update (get last-updated profile))
        (blocks-passed (- block-height last-update))
        ;; Simple decay: reduce by 1 point per 1000 blocks
        (decay-amount (/ blocks-passed u1000))
        (current-score (if (> base-score decay-amount) 
                         (- base-score decay-amount) 
                         u0))
      )
      (ok current-score)
    )
    ERR_USER_NOT_FOUND
  )
)

;; Check if user meets credibility threshold for domain
(define-read-only (verify-credibility-threshold (user principal) (domain (string-ascii 50)))
  (match (map-get? reputation-domains domain)
    domain-info
    (match (get-current-reputation user)
      current-score
      (ok (>= current-score (get min-score domain-info)))
      error-val (err error-val)
    )
    (ok false)
  )
)

;; Get verifier info
(define-read-only (get-verifier-info (verifier principal))
  (map-get? verifiers verifier)
)

;; Validate credibility proof
(define-read-only (validate-credibility-proof (proof-hash (buff 32)))
  (match (map-get? credibility-proofs proof-hash)
    proof-data
    (ok (and 
      (get is-valid proof-data)
      (< block-height (get expiry-height proof-data))
    ))
    (ok false)
  )
)

;; Public functions

;; Initialize user profile
(define-public (initialize-user-profile)
  (let
    (
      (user-id (var-get next-user-id))
    )
    (asserts! (is-none (map-get? user-profiles tx-sender)) ERR_UNAUTHORIZED)
    
    ;; Create user profile
    (map-set user-profiles tx-sender
      {
        user-id: user-id,
        reputation-score: u0,
        stake-amount: u0,
        last-updated: block-height,
        verification-count: u0,
        is-verified: false
      }
    )
    
    ;; Increment next user ID
    (var-set next-user-id (+ user-id u1))
    (ok user-id)
  )
)

;; Stake tokens for reputation building
(define-public (stake-for-reputation (amount uint))
  (let
    (
      (current-profile (unwrap! (map-get? user-profiles tx-sender) ERR_USER_NOT_FOUND))
      (new-stake-amount (+ (get stake-amount current-profile) amount))
    )
    (asserts! (>= amount MIN_STAKE_AMOUNT) ERR_INSUFFICIENT_STAKE)
    
    ;; Transfer STX to contract
    (try! (stx-transfer? amount tx-sender (as-contract tx-sender)))
    
    ;; Update user profile
    (map-set user-profiles tx-sender
      (merge current-profile 
        {
          stake-amount: new-stake-amount,
          last-updated: block-height
        }
      )
    )
    (ok new-stake-amount)
  )
)

;; Register as a verifier
(define-public (register-verifier (stake-amount uint))
  (begin
    (asserts! (>= stake-amount (* MIN_STAKE_AMOUNT u5)) ERR_INSUFFICIENT_STAKE) ;; Verifiers need 5x minimum stake
    
    ;; Transfer stake
    (try! (stx-transfer? stake-amount tx-sender (as-contract tx-sender)))
    
    ;; Register verifier
    (map-set verifiers tx-sender
      {
        is-active: true,
        stake-amount: stake-amount,
        attestation-count: u0,
        reputation: u100 ;; Starting reputation for verifiers
      }
    )
    (ok true)
  )
)

;; Submit credibility attestation (only verifiers)
(define-public (submit-attestation 
  (target principal) 
  (score uint) 
  (domain (string-ascii 50))
  (proof-hash (buff 32)))
  (let
    (
      (verifier-info (unwrap! (map-get? verifiers tx-sender) ERR_UNAUTHORIZED))
      (target-profile (unwrap! (map-get? user-profiles target) ERR_USER_NOT_FOUND))
    )
    (asserts! (get is-active verifier-info) ERR_UNAUTHORIZED)
    (asserts! (<= score u1000) ERR_INVALID_SCORE) ;; Max score of 1000
    
    ;; Record attestation
    (map-set attestations { attester: tx-sender, target: target }
      {
        score: score,
        timestamp: block-height,
        domain: domain,
        proof-hash: proof-hash
      }
    )
    
    ;; Update target's reputation score
    (let
      (
        (current-score (get reputation-score target-profile))
        ;; Simple weighted average with existing score
        (new-score (/ (+ current-score score) u2))
        (new-verification-count (+ (get verification-count target-profile) u1))
      )
      (map-set user-profiles target
        (merge target-profile
          {
            reputation-score: new-score,
            last-updated: block-height,
            verification-count: new-verification-count,
            is-verified: (>= new-verification-count u3) ;; Verified after 3 attestations
          }
        )
      )
    )
    
    ;; Update verifier stats
    (map-set verifiers tx-sender
      (merge verifier-info
        {
          attestation-count: (+ (get attestation-count verifier-info) u1)
        }
      )
    )
    
    (ok true)
  )
)

;; Generate credibility proof for external verification
(define-public (generate-credibility-proof (score-threshold uint) (expiry-blocks uint))
  (let
    (
      (user-profile (unwrap! (map-get? user-profiles tx-sender) ERR_USER_NOT_FOUND))
      (current-score (unwrap! (get-current-reputation tx-sender) ERR_USER_NOT_FOUND))
      (proof-hash (keccak256 (concat 
        (concat
          (unwrap-panic (to-consensus-buff? tx-sender))
          (unwrap-panic (to-consensus-buff? score-threshold))
        )
        (unwrap-panic (to-consensus-buff? block-height))
      )))
    )
    (asserts! (>= current-score score-threshold) ERR_INSUFFICIENT_STAKE)
    (asserts! (get is-verified user-profile) ERR_PROOF_VERIFICATION_FAILED)
    
    ;; Create proof
    (map-set credibility-proofs proof-hash
      {
        user: tx-sender,
        score-threshold: score-threshold,
        expiry-height: (+ block-height expiry-blocks),
        is-valid: true
      }
    )
    
    (ok proof-hash)
  )
)

;; Add reputation domain (admin only)
(define-public (add-reputation-domain 
  (domain (string-ascii 50))
  (min-score uint)
  (decay-rate uint))
  (begin
    (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_UNAUTHORIZED)
    
    (map-set reputation-domains domain
      {
        min-score: min-score,
        decay-rate: decay-rate,
        is-active: true
      }
    )
    (ok true)
  )
)

;; Withdraw stake (partial implementation)
(define-public (withdraw-stake (amount uint))
  (let
    (
      (user-profile (unwrap! (map-get? user-profiles tx-sender) ERR_USER_NOT_FOUND))
      (current-stake (get stake-amount user-profile))
    )
    (asserts! (<= amount current-stake) ERR_INSUFFICIENT_STAKE)
    (asserts! (>= (- current-stake amount) MIN_STAKE_AMOUNT) ERR_INSUFFICIENT_STAKE)
    
    ;; Transfer STX back to user
    (try! (as-contract (stx-transfer? amount tx-sender tx-sender)))
    
    ;; Update stake amount
    (map-set user-profiles tx-sender
      (merge user-profile
        {
          stake-amount: (- current-stake amount),
          last-updated: block-height
        }
      )
    )
    (ok true)
  )
)