package builtInFunctions

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync/atomic"

	coredrwa "github.com/multiversx/mx-chain-core-go/data/drwa"
	logger "github.com/multiversx/mx-chain-logger-go"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
)

var logDRWA = logger.GetOrCreate("builtInFunctions/drwa")

const (
	drwaTokenPolicyPrefix       = string(coredrwa.TokenPolicyPrefix)
	drwaHolderMirrorPrefix      = string(coredrwa.HolderMirrorPrefix)
	drwaHolderProfilePrefix     = string(coredrwa.HolderProfilePrefix)
	drwaHolderAuditorAuthPrefix = string(coredrwa.HolderAuditorAuthPrefix)
	drwaActivePrefix            = "drwa:active:"
	drwaNilTrieErrorMessage     = "trie is nil"
	// drwaReadGasUnitsDefault is the default gas multiplier per compliance read.
	// Set to 10 to account for the real cost of trie traversal + deserialization
	// per state read. Each side of a transfer performs up to 4 reads (policy,
	// holder mirror, profile, auditor auth). Value validated against DataCopyPerByte
	// benchmarks — 10x baseline is the minimum that prevents gas-price arbitrage on
	// regulated token spam.
	drwaReadGasUnitsDefault = 10

	// G-08: Named constants for binary decoder minimum payload sizes.
	// These replace magic numbers throughout the binary decoders and make
	// size requirements discoverable via code search.

	// drwaBinaryTokenPolicyMinSize is the minimum valid binary token policy payload.
	// Layout: 4 boolean flags (bytes 0-3) + 8 reserved zero bytes (bytes 4-11).
	drwaBinaryTokenPolicyMinSize = 12

	// drwaBinaryHolderPayloadMinSize is the minimum binary holder mirror payload.
	// Layout: 8-byte holder_policy_version prefix.
	drwaBinaryHolderPayloadMinSize = 8

	// drwaBinaryHolderTrailerMinSize is the minimum trailer after the four
	// length-prefixed string fields in a binary holder mirror payload.
	// Layout: 8-byte ExpiryRound + 3 boolean bytes (TransferLocked, ReceiveLocked, AuditorAuthorized).
	drwaBinaryHolderTrailerMinSize = 11

	// drwaBinaryProfilePayloadMinSize is the minimum binary holder profile payload.
	// Layout: 8-byte stored version prefix (same as holder mirror).
	drwaBinaryProfilePayloadMinSize = 8

	// drwaBinaryAuditorAuthPayloadMinSize is the minimum binary auditor authorization payload.
	// Layout: 8 reserved bytes + 1 authorization boolean.
	drwaBinaryAuditorAuthPayloadMinSize = 9

	// F-008: Minimum gas cost returned by computeDRWAReadGasCost when the
	// computed cost would otherwise be zero. Prevents free compliance reads
	// when both DataCopyPerByte and fallbackCost are zero (misconfigured schedule).
	drwaMinReadGasCost = 1000
)

// drwaReadGasUnitsAtomic is the configurable gas multiplier per compliance storage read.
// Defaults to drwaReadGasUnitsDefault. Configurable via SetDRWAReadGasUnits
// for gas schedule integration. Uses atomic operations to prevent data races
// when read concurrently by transfer processing goroutines.
var drwaReadGasUnitsAtomic atomic.Uint64

func init() {
	drwaReadGasUnitsAtomic.Store(drwaReadGasUnitsDefault)
}

// SetDRWAReadGasUnits allows the gas schedule to configure the DRWA compliance
// read cost. Must be called during node initialization, before any transfers
// are processed. Zero values are rejected to prevent free compliance checks.
func SetDRWAReadGasUnits(units uint64) {
	if units == 0 {
		return // Reject zero — would make compliance checks free
	}
	drwaReadGasUnitsAtomic.Store(units)
}

// Exported constants for cross-module validation.
// The sync adapter in mx-chain-go MUST use identical prefix values.
// Any divergence silently breaks the entire enforcement system.
const (
	DRWATokenPolicyPrefix       = drwaTokenPolicyPrefix
	DRWAHolderMirrorPrefix      = drwaHolderMirrorPrefix
	DRWAHolderProfilePrefix     = drwaHolderProfilePrefix
	DRWAHolderAuditorAuthPrefix = drwaHolderAuditorAuthPrefix
	DRWAAssetRecordPrefix       = string(coredrwa.AssetRecordPrefix)

	// DRWAMaxFieldBytes caps the length of any single binary field. Exported so
	// mx-chain-go sync layer can reference the same limit (F-022).
	DRWAMaxFieldBytes = 64 * 1024
)

var (
	errDRWAPolicyNotSynced          = errors.New(string(coredrwa.DenialPolicyNotSynced)) // code 0 — regulated token has no synced policy
	errDRWATokenPaused              = errors.New(string(coredrwa.DenialTokenPaused))     // code 1
	errDRWAKYCRequiredSender        = errors.New(string(coredrwa.DenialKYCRequiredSender))
	errDRWAAMLBlockedSender         = errors.New(string(coredrwa.DenialAMLBlockedSender))
	errDRWAAssetExpired             = errors.New(string(coredrwa.DenialAssetExpired))
	errDRWATransferLocked           = errors.New(string(coredrwa.DenialTransferLocked))
	errDRWAKYCRequiredReceiver      = errors.New(string(coredrwa.DenialKYCRequiredReceiver))
	errDRWAAMLBlockedReceiver       = errors.New(string(coredrwa.DenialAMLBlockedReceiver))
	errDRWAReceiveLocked            = errors.New(string(coredrwa.DenialReceiveLocked))
	errDRWAInvestorClass            = errors.New(string(coredrwa.DenialInvestorClass))
	errDRWAJurisdiction             = errors.New(string(coredrwa.DenialJurisdiction))
	errDRWAAuditorRequired          = errors.New(string(coredrwa.DenialAuditorRequired))    // code 11
	errDRWATravelRuleRequired       = errors.New(string(coredrwa.DenialTravelRuleRequired)) // code 12 — FATF Travel Rule attestation missing
	errDRWASanctionsMatch           = errors.New(string(coredrwa.DenialSanctionsMatch))     // code 13 — holder failed sanctions screening
	errDRWAWindDownActive           = errors.New(string(coredrwa.DenialWindDownActive))     // code 14 — MiCA orderly wind-down in progress
	errDRWANilAccountsAdapter       = errors.New("nil DRWA accounts adapter")
	errDRWAStateReaderMissing       = errors.New("DRWA_STATE_READER_MISSING")
	errDRWAStateReaderAttachMissing = errors.New("DRWA state reader factory returned nil")
	errDRWABinaryFieldOverflow      = errors.New("DRWA_BINARY_FIELD_OVERFLOW")
)

const (
	drwaLogSenderDenied   = "drwa sender transfer denied"
	drwaLogReceiverDenied = "drwa receiver transfer denied"
	drwaLogMetadataDenied = "drwa metadata update denied"
)

type drwaDecision struct {
	Allowed    bool
	DenialCode error
}

type drwaTokenPolicyView struct {
	DRWAEnabled               bool            `json:"drwa_enabled"`
	GlobalPause               bool            `json:"global_pause"`
	StrictAuditorMode         bool            `json:"strict_auditor_mode"`
	MetadataProtectionEnabled bool            `json:"metadata_protection_enabled"`
	TokenPolicyVersion        uint64          `json:"token_policy_version,omitempty"`
	AllowedInvestorClasses    map[string]bool `json:"allowed_investor_classes,omitempty"`
	AllowedJurisdictions      map[string]bool `json:"allowed_jurisdictions,omitempty"`
	// : FATF Travel Rule — when true, both sender and receiver must have
	// TravelRuleAttested=true in their holder mirror before a transfer is allowed.
	// Enforcement integrates with off-chain VASP travel rule protocols (e.g., TRISA, OpenVASP).
	TravelRuleRequired bool `json:"travel_rule_required,omitempty"`
	// : Sanctions screening — when true, both sender and receiver must have
	// SanctionsCleared=true in their holder mirror. Sanctions attestations are
	// managed off-chain and synced via identity-registry.
	SanctionsScreeningEnabled bool `json:"sanctions_screening_enabled,omitempty"`
	// MiCA: IPFS CID of the registered white paper. Informational — no
	// enforcement in the transfer gate, but exposed for indexer/API queries.
	WhitePaperCid string `json:"white_paper_cid,omitempty"`
	// MiCA: Registration status lifecycle (draft/submitted/approved/rejected/withdrawn).
	// Informational — exposed for indexer/API queries.
	RegistrationStatus string `json:"registration_status,omitempty"`
	// MiCA orderly wind-down: when true, all transfers are denied.
	// Set by the asset-manager contract via initiateWindDown and synced
	// to the token policy key so the transfer gate can read it.
	WindDownInitiated bool `json:"wind_down_initiated,omitempty"`
}

// drwaAssetRecordView is the Go-side representation of the synced asset record
// stored under the drwa:asset: prefix in the system account. Used by the
// transfer gate to enforce wind-down restrictions.
type drwaAssetRecordView struct {
	// MiCA orderly wind-down: when true, all transfers are denied.
	WindDownInitiated bool   `json:"wind_down_initiated,omitempty"`
	WindDownRound     uint64 `json:"wind_down_round,omitempty"`
}

type drwaHolderMirrorView struct {
	KYCStatus              string `json:"kyc_status"`
	AMLStatus              string `json:"aml_status"`
	InvestorClass          string `json:"investor_class,omitempty"`
	JurisdictionCode       string `json:"jurisdiction_code,omitempty"`
	ExpiryRound            uint64 `json:"expiry_round,omitempty"`
	PolicyVersionEvaluated uint64 `json:"policy_version_evaluated,omitempty"`
	IdentityExpiryRound    uint64 `json:"-"`
	// storedVersion is populated during decode from the drwaStoredValue wrapper.
	// Used to resolve merge precedence when both holder mirror and profile exist.
	storedVersion uint64
	// TransferLocked and ReceiveLocked are top-level fields whose JSON tags
	// match the DrwaHolderMirror struct fields serialized by the Rust contracts.
	// They must NOT be stored in a nested map — json.Unmarshal cannot populate
	// map entries from top-level JSON keys.
	TransferLocked    bool `json:"transfer_locked"`
	ReceiveLocked     bool `json:"receive_locked"`
	AuditorAuthorized bool `json:"auditor_authorized"`
	// RH-1: SEC Rule 144 — transfer lock until a specific round. If non-zero and
	// the current round is less than this value, sender-side transfers are denied.
	// Written by asset-manager via syncHolderCompliance. Rust-side: DrwaHolderMirror
	// must include a lock_until_round field synced through the holder mirror body.
	LockUntilRound uint64 `json:"lock_until_round,omitempty"`
	// : FATF Travel Rule — set to true when the holder has a valid travel rule
	// attestation from an authorized VASP. Synced via identity-registry.
	TravelRuleAttested bool `json:"travel_rule_attested,omitempty"`
	// : Sanctions screening — set to true when the holder has passed sanctions
	// screening. SanctionsScreeningCid holds the CID of the off-chain attestation
	// for audit trail purposes.
	SanctionsCleared      bool   `json:"sanctions_cleared,omitempty"`
	SanctionsScreeningCid string `json:"sanctions_screening_cid,omitempty"`
	// RH-6: Beneficial ownership (UBO) tracking — populated by identity-registry
	// sync. Used for audit/reporting only, no enforcement logic.
	UboParentEntity string `json:"ubo_parent_entity,omitempty"`
	OwnershipPct    uint32 `json:"ownership_pct,omitempty"`
}

type drwaHolderProfileView struct {
	KYCStatus        string `json:"kyc_status"`
	AMLStatus        string `json:"aml_status"`
	InvestorClass    string `json:"investor_class,omitempty"`
	JurisdictionCode string `json:"jurisdiction_code,omitempty"`
	ExpiryRound      uint64 `json:"expiry_round,omitempty"`
	storedVersion    uint64
}

type drwaHolderAuditorAuthorizationView struct {
	AuditorAuthorized bool `json:"auditor_authorized,omitempty"`
	storedVersion     uint64
}

type drwaStateReader interface {
	GetTokenPolicy(tokenIdentifier []byte) (*drwaTokenPolicyView, error)
	GetHolderMirror(tokenIdentifier []byte, address []byte, currentAccount vmcommon.UserAccountHandler) (*drwaHolderMirrorView, error)
	GetAssetRecord(tokenIdentifier []byte) (*drwaAssetRecordView, error)
	IsDRWAActive(tokenIdentifier []byte) (bool, error)
}

type drwaAccountsReader struct {
	accounts vmcommon.AccountsAdapter
}

type drwaStoredValue struct {
	Version uint64 `json:"version"`
	Body    []byte `json:"body"`
}

func newDRWAAccountsReader(accounts vmcommon.AccountsAdapter) (*drwaAccountsReader, error) {
	if accounts == nil || accounts.IsInterfaceNil() {
		return nil, errDRWANilAccountsAdapter
	}

	return &drwaAccountsReader{accounts: accounts}, nil
}

// IsInterfaceNil returns true if there is no value under the interface
func (d *drwaAccountsReader) IsInterfaceNil() bool {
	return d == nil
}

// BuildDRWATokenPolicyKey constructs the storage key for a token's policy entry.
// Exported so mx-chain-go sync adapter can reuse the canonical key builder.
// Returns nil if tokenIdentifier is empty — callers must check for nil and
// return an appropriate error.
func BuildDRWATokenPolicyKey(tokenIdentifier []byte) []byte {
	if len(tokenIdentifier) == 0 {
		return nil
	}
	return []byte(drwaTokenPolicyPrefix + hex.EncodeToString(tokenIdentifier) + ":policy")
}

// BuildDRWAHolderMirrorKey constructs the storage key for a holder's mirror entry.
// Exported so mx-chain-go sync adapter can reuse the canonical key builder.
// Returns nil if tokenIdentifier or address is empty.
func BuildDRWAHolderMirrorKey(tokenIdentifier []byte, address []byte) []byte {
	if len(tokenIdentifier) == 0 || len(address) == 0 {
		return nil
	}
	return []byte(drwaHolderMirrorPrefix + hex.EncodeToString(tokenIdentifier) + ":" + hex.EncodeToString(address))
}

// BuildDRWAHolderProfileKey constructs the storage key for a holder's profile entry.
// Exported so mx-chain-go sync adapter can reuse the canonical key builder.
// Returns nil if address is empty.
func BuildDRWAHolderProfileKey(address []byte) []byte {
	if len(address) == 0 {
		return nil
	}
	return []byte(drwaHolderProfilePrefix + hex.EncodeToString(address))
}

// BuildDRWAHolderAuditorAuthorizationKey constructs the storage key for a holder's auditor authorization entry.
// Exported so mx-chain-go sync adapter can reuse the canonical key builder.
// Returns nil if tokenIdentifier or address is empty.
func BuildDRWAHolderAuditorAuthorizationKey(tokenIdentifier []byte, address []byte) []byte {
	if len(tokenIdentifier) == 0 || len(address) == 0 {
		return nil
	}
	return []byte(drwaHolderAuditorAuthPrefix + hex.EncodeToString(tokenIdentifier) + ":" + hex.EncodeToString(address))
}

// BuildDRWAAssetRecordKey constructs the storage key for a token's asset record.
// Exported so mx-chain-go sync adapter can reuse the canonical key builder.
// Returns nil if tokenIdentifier is empty.
func BuildDRWAAssetRecordKey(tokenIdentifier []byte) []byte {
	if len(tokenIdentifier) == 0 {
		return nil
	}
	return []byte(DRWAAssetRecordPrefix + hex.EncodeToString(tokenIdentifier) + ":record")
}

// BuildDRWAActiveKey constructs the storage key for a token's DRWA-active marker.
// Exported so mx-chain-go can reuse the canonical key builder.
// Returns nil if tokenIdentifier is empty.
func BuildDRWAActiveKey(tokenIdentifier []byte) []byte {
	if len(tokenIdentifier) == 0 {
		return nil
	}
	return []byte(drwaActivePrefix + hex.EncodeToString(tokenIdentifier))
}

func (d *drwaAccountsReader) GetAssetRecord(tokenIdentifier []byte) (*drwaAssetRecordView, error) {
	key := BuildDRWAAssetRecordKey(tokenIdentifier)
	if key == nil {
		return nil, fmt.Errorf("drwa asset record: empty token identifier")
	}

	systemAccount, err := getSystemAccount(d.accounts)
	if err != nil {
		return nil, err
	}

	data, err := retrieveOptionalDRWAValue(systemAccount, key)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, nil
	}

	record := &drwaAssetRecordView{}
	err = decodeDRWAStoredJSON(data, record)
	if err != nil {
		return nil, fmt.Errorf("drwa asset record unmarshal: %w", err)
	}

	return record, nil
}

func (d *drwaAccountsReader) IsDRWAActive(tokenIdentifier []byte) (bool, error) {
	key := BuildDRWAActiveKey(tokenIdentifier)
	if key == nil {
		return false, fmt.Errorf("drwa active marker: empty token identifier")
	}

	systemAccount, err := getSystemAccount(d.accounts)
	if err != nil {
		return false, err
	}

	data, err := retrieveOptionalDRWAValue(systemAccount, key)
	if err != nil {
		return false, err
	}

	return len(data) > 0, nil
}

func (d *drwaAccountsReader) GetTokenPolicy(tokenIdentifier []byte) (*drwaTokenPolicyView, error) {
	key := BuildDRWATokenPolicyKey(tokenIdentifier)
	if key == nil {
		return nil, fmt.Errorf("drwa token policy: empty token identifier")
	}

	systemAccount, err := getSystemAccount(d.accounts)
	if err != nil {
		return nil, err
	}

	data, err := retrieveOptionalDRWAValue(systemAccount, key)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, nil
	}

	policy := &drwaTokenPolicyView{}
	err = decodeDRWAStoredJSON(data, policy)
	if err != nil {
		return nil, fmt.Errorf("drwa token policy unmarshal: %w", err)
	}

	return policy, nil
}

func (d *drwaAccountsReader) GetHolderMirror(tokenIdentifier []byte, address []byte, currentAccount vmcommon.UserAccountHandler) (*drwaHolderMirrorView, error) {
	mirrorKey := BuildDRWAHolderMirrorKey(tokenIdentifier, address)
	if mirrorKey == nil {
		return nil, fmt.Errorf("drwa holder mirror: empty token identifier or address")
	}
	profileKey := BuildDRWAHolderProfileKey(address)
	if profileKey == nil {
		return nil, fmt.Errorf("drwa holder profile: empty address")
	}
	auditorKey := BuildDRWAHolderAuditorAuthorizationKey(tokenIdentifier, address)
	if auditorKey == nil {
		return nil, fmt.Errorf("drwa holder auditor auth: empty token identifier or address")
	}

	account, err := d.loadUserAccount(address, currentAccount)
	if err != nil {
		return nil, err
	}
	if account == nil {
		return nil, nil
	}

	var holder *drwaHolderMirrorView
	data, err := retrieveOptionalDRWAValue(account, mirrorKey)
	if err != nil {
		return nil, err
	}
	if len(data) > 0 {
		holder = &drwaHolderMirrorView{}
		err = decodeDRWAStoredJSON(data, holder)
		if err != nil {
			return nil, fmt.Errorf("drwa holder mirror unmarshal: %w", err)
		}
	}

	var profile *drwaHolderProfileView
	profileData, err := retrieveOptionalDRWAValue(account, profileKey)
	if err != nil {
		return nil, err
	}
	if len(profileData) > 0 {
		profile = &drwaHolderProfileView{}
		err = decodeDRWAStoredJSON(profileData, profile)
		if err != nil {
			return nil, fmt.Errorf("drwa holder profile unmarshal: %w", err)
		}
	}

	var auditorAuth *drwaHolderAuditorAuthorizationView
	auditorData, err := retrieveOptionalDRWAValue(account, auditorKey)
	if err != nil {
		return nil, err
	}
	if len(auditorData) > 0 {
		auditorAuth = &drwaHolderAuditorAuthorizationView{}
		err = decodeDRWAStoredJSON(auditorData, auditorAuth)
		if err != nil {
			return nil, fmt.Errorf("drwa holder auditor auth unmarshal: %w", err)
		}
	}

	if holder == nil && profile == nil && auditorAuth == nil {
		logDRWA.Debug("drwa: holder, profile, and auditor auth all nil for regulated token",
			"token", string(tokenIdentifier), "address", hex.EncodeToString(address))
		recordDRWAGateMetric("gate_holder_records_all_missing")
		return nil, nil
	}

	merged := &drwaHolderMirrorView{}
	if holder != nil {
		if holder.KYCStatus != "" {
			merged.KYCStatus = holder.KYCStatus
		}
		if holder.AMLStatus != "" {
			merged.AMLStatus = holder.AMLStatus
		}
		if holder.InvestorClass != "" {
			merged.InvestorClass = holder.InvestorClass
		}
		if holder.JurisdictionCode != "" {
			merged.JurisdictionCode = holder.JurisdictionCode
		}
		if holder.ExpiryRound != 0 {
			merged.ExpiryRound = holder.ExpiryRound
		}
		merged.TransferLocked = holder.TransferLocked
		merged.ReceiveLocked = holder.ReceiveLocked
		merged.AuditorAuthorized = holder.AuditorAuthorized
		merged.LockUntilRound = holder.LockUntilRound
		merged.TravelRuleAttested = holder.TravelRuleAttested
		merged.SanctionsCleared = holder.SanctionsCleared
		merged.SanctionsScreeningCid = holder.SanctionsScreeningCid
		merged.UboParentEntity = holder.UboParentEntity
		merged.OwnershipPct = holder.OwnershipPct
	}
	if profile != nil {
		// Only let profile overwrite shared compliance fields if its
		// version is >= the holder mirror version. This prevents a stale
		// profile sync from reverting a newer holder mirror update.
		// Strict > (not >=). Equal versions means both were written
		// in the same sync cycle — holder mirror is authoritative for shared
		// fields because asset-manager writes it with token-specific context.
		profileWins := holder == nil || profile.storedVersion > holder.storedVersion
		if profileWins {
			merged.KYCStatus = profile.KYCStatus
			merged.AMLStatus = profile.AMLStatus
			merged.InvestorClass = profile.InvestorClass
			merged.JurisdictionCode = profile.JurisdictionCode
		}
		// L-5: At equal versions, holder mirror wins for shared fields (ExpiryRound, KycStatus, etc.)
		// but IdentityExpiryRound falls through to the profile if not yet set on the merged result.
		// This is intentional: IdentityExpiryRound is identity-registry-specific and may not be
		// present in the holder mirror, while ExpiryRound is policy-level.
		if profileWins || merged.IdentityExpiryRound == 0 {
			merged.IdentityExpiryRound = profile.ExpiryRound
		}
		if merged.ExpiryRound == 0 && profileWins {
			merged.ExpiryRound = profile.ExpiryRound
		}
	}
	if auditorAuth != nil {
		// Attestation-owned auditor authorization is authoritative whenever
		// present. A separate HolderAuditorAuthorization record must override
		// any historical copy embedded in HolderMirror so compliance syncs from
		// asset-manager cannot overwrite a valid attestation state.
		merged.AuditorAuthorized = auditorAuth.AuditorAuthorized
	}

	return merged, nil
}

func (d *drwaAccountsReader) loadUserAccount(address []byte, currentAccount vmcommon.UserAccountHandler) (vmcommon.UserAccountHandler, error) {
	if currentAccount != nil && !currentAccount.IsInterfaceNil() && bytes.Equal(currentAccount.AddressBytes(), address) {
		return currentAccount, nil
	}

	accountHandler, err := d.accounts.LoadAccount(address)
	if err != nil {
		return nil, err
	}

	userAccount, ok := accountHandler.(vmcommon.UserAccountHandler)
	if !ok {
		return nil, ErrWrongTypeAssertion
	}

	return userAccount, nil
}

func retrieveOptionalDRWAValue(account vmcommon.UserAccountHandler, key []byte) ([]byte, error) {
	data, _, err := account.AccountDataHandler().RetrieveValue(key)
	if err == nil {
		return data, nil
	}
	if len(account.GetRootHash()) == 0 && strings.Contains(err.Error(), drwaNilTrieErrorMessage) {
		return nil, nil
	}

	return nil, err
}

func decodeDRWAStoredJSON(data []byte, destination interface{}) error {
	// P0 security: reject oversized payloads before JSON parsing to prevent
	// resource exhaustion from deeply nested or excessively large JSON blobs.
	// 64KB aligns with the binary decoder's per-field cap.
	const drwaMaxStoredJSONSize = 65536
	if len(data) > drwaMaxStoredJSONSize {
		return fmt.Errorf("drwa stored JSON exceeds size limit: %d > %d", len(data), drwaMaxStoredJSONSize)
	}

	storedValue := &drwaStoredValue{}
	jsonErr := json.Unmarshal(data, storedValue)
	var err error
	if jsonErr == nil && len(storedValue.Body) > 0 {
		err = decodeDRWABody(storedValue.Body, destination)
		// Propagate stored version for merge precedence
		if err == nil {
			switch typed := destination.(type) {
			case *drwaHolderMirrorView:
				typed.storedVersion = storedValue.Version
			case *drwaHolderProfileView:
				typed.storedVersion = storedValue.Version
			case *drwaHolderAuditorAuthorizationView:
				typed.storedVersion = storedValue.Version
			}
		}
	} else {
		if jsonErr == nil {
			err = errors.New("missing drwa wrapped body")
		} else {
			err = jsonErr
		}
	}
	if err != nil {
		recordDRWADecodeFailure(data, destination, err)
	}
	return err
}

func recordDRWADecodeFailure(data []byte, destination interface{}, err error) {
	logDRWA.Warn("drwa stored value decode failure", "error", err, "metric", classifyDRWADecodeFailureMetric(data, destination, err))
	recordDRWAGateMetric(drwaGateMetricDecodeFailure)
	recordDRWAGateMetric(classifyDRWADecodeFailureMetric(data, destination, err))
}

func classifyDRWADecodeFailureMetric(data []byte, destination interface{}, err error) string {
	if len(data) == 0 {
		return drwaGateMetricDecodeFailureMissing
	}
	if data[0] == '{' {
		return drwaGateMetricDecodeFailureJSON
	}

	if errors.Is(err, errDRWABinaryFieldOverflow) {
		return drwaGateMetricDecodeFailureBinary
	}
	switch destination.(type) {
	case *drwaTokenPolicyView, *drwaHolderMirrorView, *drwaHolderProfileView, *drwaHolderAuditorAuthorizationView:
		return drwaGateMetricDecodeFailureBinary
	default:
		return drwaGateMetricDecodeFailure
	}
}

func decodeDRWABody(data []byte, destination interface{}) error {
	// Bodies that start with '{' are JSON-format.  Do not fall back to the
	// binary decoder when JSON parsing fails: a corrupt JSON body must surface
	// as a parse error.  Silently re-routing to the binary decoder would drop
	// AllowedInvestorClasses / AllowedJurisdictions enforcement entirely.
	//
	// BINARY FORMAT LIMITATION: The binary token policy decoder cannot
	// encode AllowedInvestorClasses/AllowedJurisdictions maps. The Rust
	// policy-registry contract uses JSON when these fields are populated.
	// A Rust contract bug that serializes restricted policies in binary
	// format would silently allow all classes/jurisdictions. This is safe
	// under the current contract implementation but fragile — any change to
	// the Rust serialization path must be verified against this decoder.
	if len(data) > 0 && data[0] == '{' {
		err := json.Unmarshal(data, destination)
		if err != nil {
			return err
		}
		// F-021: Pre-normalize map keys to lowercase at decode time so that
		// drwaMapContainsFold can do direct map lookup instead of O(n) iteration.
		if policy, ok := destination.(*drwaTokenPolicyView); ok {
			policy.AllowedInvestorClasses = drwaNormalizeMapKeys(policy.AllowedInvestorClasses)
			policy.AllowedJurisdictions = drwaNormalizeMapKeys(policy.AllowedJurisdictions)
		}
		return nil
	}

	switch typedDestination := destination.(type) {
	case *drwaTokenPolicyView:
		return decodeDRWABinaryTokenPolicy(data, typedDestination)
	case *drwaHolderMirrorView:
		return decodeDRWABinaryHolderMirror(data, typedDestination)
	case *drwaHolderProfileView:
		return decodeDRWABinaryHolderProfile(data, typedDestination)
	case *drwaHolderAuditorAuthorizationView:
		return decodeDRWABinaryHolderAuditorAuthorization(data, typedDestination)
	default:
		return json.Unmarshal(data, destination)
	}
}

func decodeDRWABinaryTokenPolicy(data []byte, destination *drwaTokenPolicyView) error {
	if len(data) < drwaBinaryTokenPolicyMinSize {
		return errors.New("invalid DRWA binary token policy payload")
	}
	if len(data) != drwaBinaryTokenPolicyMinSize {
		return fmt.Errorf("invalid DRWA binary token policy payload length: got %d, expected %d", len(data), drwaBinaryTokenPolicyMinSize)
	}

	destination.DRWAEnabled = data[0] == 1
	destination.GlobalPause = data[1] == 1
	destination.StrictAuditorMode = data[2] == 1
	destination.MetadataProtectionEnabled = data[3] == 1

	// Validate bytes 4-11 are zero. Reserved bytes must not contain
	// arbitrary data (prevents covert channels and future format confusion).
	for i := 4; i < drwaBinaryTokenPolicyMinSize && i < len(data); i++ {
		if data[i] != 0 {
			return fmt.Errorf("DRWA binary policy byte %d is non-zero (%d): reserved bytes must be 0", i, data[i])
		}
	}

	// Binary format cannot encode AllowedInvestorClasses/AllowedJurisdictions.
	// Nil maps therefore mean "no restriction". Only the exact 12-byte
	// boolean-only format is accepted here; trailing bytes are rejected above so
	// future/buggy encoders cannot silently append ignored restriction data.
	// Restricted policies must be synced as JSON by the Rust policy-registry.
	if destination.DRWAEnabled {
		recordDRWAGateMetric("binary_policy_decode_enabled")
		if destination.AllowedInvestorClasses == nil && destination.AllowedJurisdictions == nil {
			recordDRWAGateMetric("binary_policy_no_restrictions")
		}
	}

	return nil
}

func decodeDRWABinaryHolderMirror(data []byte, destination *drwaHolderMirrorView) error {
	cursor := 0
	if len(data) < drwaBinaryHolderPayloadMinSize {
		return errors.New("invalid DRWA binary holder payload")
	}

	// First 8 bytes are the holder_policy_version (big-endian uint64).
	// Stored for storedVersion propagation in merge precedence resolution.
	holderVersion := binary.BigEndian.Uint64(data[0:8])
	destination.storedVersion = holderVersion
	cursor += 8

	kycStatus, nextCursor, err := readDRWABinaryField(data, cursor)
	if err != nil {
		return err
	}
	cursor = nextCursor

	amlStatus, nextCursor, err := readDRWABinaryField(data, cursor)
	if err != nil {
		return err
	}
	cursor = nextCursor

	investorClass, nextCursor, err := readDRWABinaryField(data, cursor)
	if err != nil {
		return err
	}
	cursor = nextCursor

	jurisdictionCode, nextCursor, err := readDRWABinaryField(data, cursor)
	if err != nil {
		return err
	}
	cursor = nextCursor

	if len(data[cursor:]) < drwaBinaryHolderTrailerMinSize {
		return errors.New("invalid DRWA binary holder trailer")
	}

	destination.KYCStatus = string(kycStatus)
	destination.AMLStatus = string(amlStatus)
	destination.InvestorClass = string(investorClass)
	destination.JurisdictionCode = string(jurisdictionCode)
	destination.ExpiryRound = binary.BigEndian.Uint64(data[cursor : cursor+8])
	// Validate boolean trailer bytes are 0 or 1 (reject malformed payloads)
	for _, idx := range []int{cursor + 8, cursor + 9, cursor + 10} {
		if data[idx] != 0 && data[idx] != 1 {
			return fmt.Errorf("DRWA binary holder byte %d invalid: %d (expected 0 or 1)", idx, data[idx])
		}
	}
	destination.TransferLocked = data[cursor+8] == 1
	destination.ReceiveLocked = data[cursor+9] == 1
	destination.AuditorAuthorized = data[cursor+10] == 1
	cursor += drwaBinaryHolderTrailerMinSize

	if len(data[cursor:]) >= 8 {
		destination.PolicyVersionEvaluated = binary.BigEndian.Uint64(data[cursor : cursor+8])
		cursor += 8
	}
	if len(data[cursor:]) != 0 {
		return fmt.Errorf("invalid DRWA binary holder trailer: %d trailing bytes", len(data[cursor:]))
	}

	return nil
}

func validateDRWAHolderPolicyFreshness(policy *drwaTokenPolicyView, holder *drwaHolderMirrorView) drwaDecision {
	if policy == nil || holder == nil || policy.TokenPolicyVersion == 0 {
		return drwaDecision{Allowed: true}
	}
	if holder.PolicyVersionEvaluated == 0 || holder.PolicyVersionEvaluated < policy.TokenPolicyVersion {
		return drwaDecision{DenialCode: errDRWAPolicyNotSynced}
	}
	return drwaDecision{Allowed: true}
}

func decodeDRWABinaryHolderProfile(data []byte, destination *drwaHolderProfileView) error {
	cursor := 0
	if len(data) < drwaBinaryProfilePayloadMinSize {
		return errors.New("invalid DRWA binary holder profile payload")
	}

	// Extract stored version for merge precedence resolution.
	destination.storedVersion = binary.BigEndian.Uint64(data[0:8])
	cursor += 8

	kycStatus, nextCursor, err := readDRWABinaryField(data, cursor)
	if err != nil {
		return err
	}
	cursor = nextCursor

	amlStatus, nextCursor, err := readDRWABinaryField(data, cursor)
	if err != nil {
		return err
	}
	cursor = nextCursor

	investorClass, nextCursor, err := readDRWABinaryField(data, cursor)
	if err != nil {
		return err
	}
	cursor = nextCursor

	jurisdictionCode, nextCursor, err := readDRWABinaryField(data, cursor)
	if err != nil {
		return err
	}
	cursor = nextCursor

	if len(data[cursor:]) < 8 {
		return errors.New("invalid DRWA binary holder profile trailer")
	}

	expiryRound := binary.BigEndian.Uint64(data[cursor : cursor+8])
	cursor += 8
	if cursor != len(data) {
		return errors.New("invalid DRWA binary holder profile trailing bytes")
	}

	destination.KYCStatus = string(kycStatus)
	destination.AMLStatus = string(amlStatus)
	destination.InvestorClass = string(investorClass)
	destination.JurisdictionCode = string(jurisdictionCode)
	destination.ExpiryRound = expiryRound

	return nil
}

// decodeDRWABinaryHolderAuditorAuthorization decodes the binary auditor
// authorization payload. Byte offset 8 carries the authorization boolean.
// Some producers also prefix the payload body with 8 version bytes to keep the
// binary layout aligned with other DRWA mirror records. Merge precedence does
// not rely on those body bytes: the wrapped drwaStoredValue.Version is the
// canonical version source used by the Go reader when reconciling holder and
// auditor authorization state.
func decodeDRWABinaryHolderAuditorAuthorization(data []byte, destination *drwaHolderAuditorAuthorizationView) error {
	if len(data) < drwaBinaryAuditorAuthPayloadMinSize {
		return errors.New("invalid DRWA binary holder auditor authorization payload")
	}

	// Validate boolean byte is 0 or 1 (reject other values)
	if data[8] != 0 && data[8] != 1 {
		return fmt.Errorf("DRWA binary auditor auth byte invalid: %d (expected 0 or 1)", data[8])
	}
	destination.AuditorAuthorized = data[8] == 1
	return nil
}

func readDRWABinaryField(data []byte, cursor int) ([]byte, int, error) {
	if len(data[cursor:]) < 4 {
		return nil, cursor, errors.New("invalid DRWA binary field length")
	}

	fieldLength := int(binary.BigEndian.Uint32(data[cursor : cursor+4]))
	// F-022: Use exported constant instead of magic number. Cap field length
	// before allocation to prevent memory exhaustion from crafted payloads.
	if fieldLength > DRWAMaxFieldBytes {
		return nil, cursor, errDRWABinaryFieldOverflow
	}
	cursor += 4
	if len(data[cursor:]) < fieldLength {
		return nil, cursor, errors.New("invalid DRWA binary field body")
	}

	field := append([]byte(nil), data[cursor:cursor+fieldLength]...)
	cursor += fieldLength

	return field, cursor, nil
}

func isDRWAEnforcementEnabled(enableEpochsHandler vmcommon.EnableEpochsHandler) bool {
	if enableEpochsHandler == nil || enableEpochsHandler.IsInterfaceNil() {
		return false
	}

	return enableEpochsHandler.IsFlagEnabled(DRWAEnforcementFlag)
}

func computeDRWAReadGasCost(baseCost vmcommon.BaseOperationCost, fallbackCost uint64, reads uint64) uint64 {
	if reads == 0 {
		return 0
	}

	unitCost := baseCost.DataCopyPerByte
	if unitCost == 0 {
		unitCost = fallbackCost
	}
	if unitCost == 0 {
		// F-008: Return minimum non-zero gas cost to prevent free compliance
		// reads when gas schedule provides zero for both base and fallback.
		return drwaMinReadGasCost
	}

	// Overflow protection for gas calculation.
	gasUnits := drwaReadGasUnitsAtomic.Load()
	if unitCost > math.MaxUint64/gasUnits {
		return math.MaxUint64
	}
	costPerRead := unitCost * gasUnits
	if reads > math.MaxUint64/costPerRead {
		return math.MaxUint64
	}
	return reads * costPerRead
}

// Upstream dependency impact assessment for DRWA compliance enforcement.
//
// RoundHandler (blockChainHook.go):
//   Provides round duration for EpochStartBlockTimeStampMs and RoundTime.
//   DRWA reads CurrentRound() for expiry checks (holder.ExpiryRound,
//   LockUntilRound). If round duration changes, time-based enforcement
//   (expiry, SEC Rule 144 lock-up) uses incorrect round-to-time mappings.
//   Impact: LOW — round numbers remain monotonically correct; only
//   wall-clock mapping shifts. No DRWA code change needed, but operators
//   must recalibrate ExpiryRound values after round duration changes.
//
// GetAllState (blockChainHook.go):
//   Returns nil; slated for upstream removal. DRWA does not use
//   GetAllState — compliance reads use per-key RetrieveValue on
//   specific system/holder accounts. No impact on DRWA.
//
// Shard merge property consolidation (esdtDataStorage.go):
//   DRWA holder mirrors are stored on the holder's shard account. On
//   shard merge, mirrors from both shards coexist without conflict because
//   keys are address-scoped. Token policies on the system account are
//   identical across shards (written by the sync adapter). Impact: NONE
//   for correctness — trie merge semantics preserve the system account's
//   DRWA keys (system account address is the same on all shards).

// MEV consideration: Compliance state changes and transfer enforcement
// execute within the same transaction context. Cross-transaction ordering
// (validator MEV) could front-run a compliance state change. Mitigation:
// compliance changes should use a commit-reveal scheme or mandatory delay
// before enforcement. See drwaSyncRecoveryTimelockBlocks in
// drwa_sync_types.go for rate-limiting on recovery_admin writes.

func isDRWARegulatedToken(reader drwaStateReader, tokenIdentifier []byte, enforcementEnabled bool) (bool, *drwaTokenPolicyView, error) {
	if reader == nil {
		if enforcementEnabled {
			recordDRWAGateMetric(drwaGateMetricReaderMissing)
			return false, nil, errDRWAStateReaderMissing
		}
		// No DRWA reader attached — token is not under DRWA regulation.
		// This is the expected state for nodes that have not enabled DRWA enforcement.
		return false, nil, nil
	}

	policy, err := reader.GetTokenPolicy(tokenIdentifier)
	if err != nil {
		return false, nil, err
	}
	if policy == nil || !policy.DRWAEnabled {
		active, activeErr := reader.IsDRWAActive(tokenIdentifier)
		if activeErr != nil {
			return false, nil, fmt.Errorf("drwa: cannot read active marker for token %s: %w", string(tokenIdentifier), activeErr)
		}
		if active {
			recordDRWAGateMetric(drwaGateMetricDeniedPolicyNotSynced)
			return true, nil, errDRWAStateReaderMissing
		}

		// If an asset record exists for this token, the token was previously
		// registered as regulated. A missing or disabled policy in that case
		// indicates corruption or unauthorized deletion — deny with
		// errDRWAPolicyNotSynced rather than silently allowing transfers.
		assetRecord, assetErr := reader.GetAssetRecord(tokenIdentifier)
		if assetErr != nil {
			// Storage error reading asset record — fail-closed.
			return false, nil, fmt.Errorf("drwa: cannot read asset record for token %s: %w", string(tokenIdentifier), assetErr)
		}
		if assetRecord != nil {
			// Asset record exists but policy is missing/disabled — this token was
			// once regulated. Deny transfers to prevent compliance escape.
			logDRWA.Warn("drwa: token has asset record but no active policy — possible policy corruption",
				"token", string(tokenIdentifier))
			recordDRWAGateMetric(drwaGateMetricDeniedPolicyNotSynced)
			return false, nil, errDRWAPolicyNotSynced
		}
		// No asset record and no policy — genuinely unregulated token. Allow.
		return false, nil, nil
	}

	return true, policy, nil
}

// validateDRWASender enforces compliance on the sending side.
// InvestorClass and Jurisdiction are checked on BOTH sender and
// receiver, which is stricter than spec S4.1 (which positions codes 9-10 as
// receiver-only). Intentional design choice: prevents non-qualified
// intermediaries from acting as distribution conduits.
func validateDRWASender(policy *drwaTokenPolicyView, holder *drwaHolderMirrorView, now uint64) drwaDecision {
	if policy == nil || !policy.DRWAEnabled {
		return drwaDecision{Allowed: true}
	}
	if policy.GlobalPause {
		return drwaDecision{DenialCode: errDRWATokenPaused}
	}
	// MiCA wind-down: when initiated, all transfers are denied.
	// Orderly wind-down requires the issuer to use a separate redemption
	// mechanism (e.g., direct burn or contract-based buyback), not peer-to-peer transfers.
	if policy.WindDownInitiated {
		return drwaDecision{DenialCode: errDRWAWindDownActive}
	}
	if holder == nil || !strings.EqualFold(holder.KYCStatus, "approved") {
		return drwaDecision{DenialCode: errDRWAKYCRequiredSender}
	}
	if freshness := validateDRWAHolderPolicyFreshness(policy, holder); !freshness.Allowed {
		return freshness
	}
	// Deny-by-default for AML — only "clear" or "approved" passes.
	if !strings.EqualFold(holder.AMLStatus, "clear") && !strings.EqualFold(holder.AMLStatus, "approved") {
		return drwaDecision{DenialCode: errDRWAAMLBlockedSender}
	}
	// If now==0 (blockchain hook not yet initialized) and holder has
	// an expiry set, deny by default — cannot validate expiry without a valid round.
	if now == 0 && (holder.IdentityExpiryRound > 0 || holder.ExpiryRound > 0) {
		return drwaDecision{DenialCode: errDRWAAssetExpired}
	}
	// F2 (closes N1): same defensive deny when round is unknown but the
	// holder has an active SEC Rule 144 lock. The original LockUntilRound
	// check below has an explicit `now > 0` guard which would silently
	// bypass the lock during the round-unknown window. Mirroring the
	// expiry deny-by-default closes that bypass.
	if now == 0 && holder.LockUntilRound > 0 {
		return drwaDecision{DenialCode: errDRWATransferLocked}
	}
	if holder.IdentityExpiryRound > 0 && now > holder.IdentityExpiryRound {
		return drwaDecision{DenialCode: errDRWAAssetExpired}
	}
	if holder.ExpiryRound > 0 && now > holder.ExpiryRound {
		return drwaDecision{DenialCode: errDRWAAssetExpired}
	}
	if holder.TransferLocked {
		return drwaDecision{DenialCode: errDRWATransferLocked}
	}
	// RH-1: SEC Rule 144 lock-up period. If lock_until_round is set and the
	// current round has not reached it, the sender cannot transfer.
	// The `now` parameter comes from the blockchain hook's current round.
	// The round-unknown (now==0) case is handled by the deny-by-default branch
	// above; this branch covers the normal-operation case.
	if holder.LockUntilRound > 0 && now > 0 && now < holder.LockUntilRound {
		return drwaDecision{DenialCode: errDRWATransferLocked}
	}
	if len(policy.AllowedInvestorClasses) > 0 && !drwaMapContainsFold(policy.AllowedInvestorClasses, holder.InvestorClass) {
		return drwaDecision{DenialCode: errDRWAInvestorClass}
	}
	if len(policy.AllowedJurisdictions) > 0 && !drwaMapContainsFold(policy.AllowedJurisdictions, holder.JurisdictionCode) {
		return drwaDecision{DenialCode: errDRWAJurisdiction}
	}
	// Strict auditor mode requires holder to have auditor
	// authorization for transfers, not just metadata updates.
	if policy.StrictAuditorMode && !holder.AuditorAuthorized {
		return drwaDecision{DenialCode: errDRWAAuditorRequired}
	}
	// : FATF Travel Rule — sender must have travel rule attestation when
	// the token policy requires it. The attestation is set by an authorized VASP
	// via identity-registry and synced to the holder mirror.
	if policy.TravelRuleRequired && !holder.TravelRuleAttested {
		return drwaDecision{DenialCode: errDRWATravelRuleRequired}
	}
	// : Sanctions screening — sender must have passed sanctions screening
	// when the token policy enables it.
	if policy.SanctionsScreeningEnabled && !holder.SanctionsCleared {
		return drwaDecision{DenialCode: errDRWASanctionsMatch}
	}

	return drwaDecision{Allowed: true}
}

func validateDRWAReceiver(policy *drwaTokenPolicyView, holder *drwaHolderMirrorView, now uint64) drwaDecision {
	if policy == nil || !policy.DRWAEnabled {
		return drwaDecision{Allowed: true}
	}
	if policy.GlobalPause {
		return drwaDecision{DenialCode: errDRWATokenPaused}
	}
	if policy.WindDownInitiated {
		return drwaDecision{DenialCode: errDRWAWindDownActive}
	}
	if holder == nil || !strings.EqualFold(holder.KYCStatus, "approved") {
		return drwaDecision{DenialCode: errDRWAKYCRequiredReceiver}
	}
	if freshness := validateDRWAHolderPolicyFreshness(policy, holder); !freshness.Allowed {
		return freshness
	}
	if !strings.EqualFold(holder.AMLStatus, "clear") && !strings.EqualFold(holder.AMLStatus, "approved") {
		return drwaDecision{DenialCode: errDRWAAMLBlockedReceiver}
	}
	// Deny-by-default when round unknown and expiry is set (receiver side).
	if now == 0 && (holder.IdentityExpiryRound > 0 || holder.ExpiryRound > 0) {
		return drwaDecision{DenialCode: errDRWAAssetExpired}
	}
	if holder.IdentityExpiryRound > 0 && now > holder.IdentityExpiryRound {
		return drwaDecision{DenialCode: errDRWAAssetExpired}
	}
	if holder.ExpiryRound > 0 && now > holder.ExpiryRound {
		return drwaDecision{DenialCode: errDRWAAssetExpired}
	}
	if holder.ReceiveLocked {
		return drwaDecision{DenialCode: errDRWAReceiveLocked}
	}
	if len(policy.AllowedInvestorClasses) > 0 && !drwaMapContainsFold(policy.AllowedInvestorClasses, holder.InvestorClass) {
		return drwaDecision{DenialCode: errDRWAInvestorClass}
	}
	if len(policy.AllowedJurisdictions) > 0 && !drwaMapContainsFold(policy.AllowedJurisdictions, holder.JurisdictionCode) {
		return drwaDecision{DenialCode: errDRWAJurisdiction}
	}
	// Receiver must also have auditor authorization when
	// strict_auditor_mode is enabled.
	if policy.StrictAuditorMode && !holder.AuditorAuthorized {
		return drwaDecision{DenialCode: errDRWAAuditorRequired}
	}
	// : FATF Travel Rule — receiver must also have travel rule attestation.
	if policy.TravelRuleRequired && !holder.TravelRuleAttested {
		return drwaDecision{DenialCode: errDRWATravelRuleRequired}
	}
	// : Sanctions screening — receiver must have passed sanctions screening.
	if policy.SanctionsScreeningEnabled && !holder.SanctionsCleared {
		return drwaDecision{DenialCode: errDRWASanctionsMatch}
	}

	return drwaDecision{Allowed: true}
}

// F-021: Map keys are pre-normalized to lowercase at decode time (see
// decodeDRWABody). Direct map lookup replaces O(n) iteration.
func drwaMapContainsFold(allowed map[string]bool, value string) bool {
	return allowed[strings.ToLower(value)]
}

// drwaNormalizeMapKeys returns a new map with all keys lowercased.
// F-021: Called at decode time so lookups can use direct map access.
func drwaNormalizeMapKeys(m map[string]bool) map[string]bool {
	if m == nil {
		return nil
	}
	normalized := make(map[string]bool, len(m))
	for k, v := range m {
		normalized[strings.ToLower(k)] = v
	}
	return normalized
}

func validateDRWAMetadataUpdate(policy *drwaTokenPolicyView, auditorAuthorized bool) drwaDecision {
	if policy == nil || !policy.DRWAEnabled {
		return drwaDecision{Allowed: true}
	}
	// GL-3: Metadata updates must respect GlobalPause — a paused token should
	// not allow any state mutation, including attribute changes.
	if policy.GlobalPause {
		return drwaDecision{DenialCode: errDRWATokenPaused}
	}
	if policy.WindDownInitiated {
		return drwaDecision{DenialCode: errDRWAWindDownActive}
	}
	if !policy.MetadataProtectionEnabled {
		return drwaDecision{Allowed: true}
	}
	if policy.StrictAuditorMode && !auditorAuthorized {
		return drwaDecision{DenialCode: errDRWAAuditorRequired}
	}

	return drwaDecision{Allowed: true}
}

func isDRWAWindDownActive(policy *drwaTokenPolicyView, assetRecord *drwaAssetRecordView) bool {
	if policy != nil && policy.WindDownInitiated {
		return true
	}
	if assetRecord != nil && assetRecord.WindDownInitiated {
		return true
	}

	return false
}

func evaluateDRWASenderTransfer(reader drwaStateReader, tokenID []byte, senderAddr []byte, senderAccount vmcommon.UserAccountHandler, now uint64) (bool, error) {
	regulated, policy, err := isDRWARegulatedToken(reader, tokenID, true)
	if err != nil || !regulated {
		return regulated, err
	}

	return evaluateDRWASenderTransferWithPolicy(reader, tokenID, policy, senderAddr, senderAccount, now)
}

func evaluateDRWASenderTransferWithPolicy(reader drwaStateReader, tokenID []byte, policy *drwaTokenPolicyView, senderAddr []byte, senderAccount vmcommon.UserAccountHandler, now uint64) (bool, error) {
	if policy == nil || !policy.DRWAEnabled {
		return false, nil
	}

	assetRecord, err := reader.GetAssetRecord(tokenID)
	if err != nil {
		return true, err
	}
	if isDRWAWindDownActive(policy, assetRecord) {
		recordDRWAGateMetric(drwaGateMetricDeniedWindDown)
		logDRWA.Warn(drwaLogSenderDenied,
			"token", string(tokenID),
			"address", hex.EncodeToString(senderAddr),
			"reason", errDRWAWindDownActive.Error(),
		)
		return true, errDRWAWindDownActive
	}

	holder, err := reader.GetHolderMirror(tokenID, senderAddr, senderAccount)
	if err != nil {
		return true, err
	}

	decision := validateDRWASender(policy, holder, now)
	if !decision.Allowed {
		if m := drwaDenialMetric(decision.DenialCode); m != "" {
			recordDRWAGateMetric(m)
		}
		logDRWA.Warn(drwaLogSenderDenied,
			"token", string(tokenID),
			"address", hex.EncodeToString(senderAddr),
			"reason", decision.DenialCode.Error(),
		)
		return true, decision.DenialCode
	}

	return true, nil
}

func checkDRWASenderTransfer(reader drwaStateReader, tokenID []byte, senderAddr []byte, senderAccount vmcommon.UserAccountHandler, now uint64) error {
	_, err := evaluateDRWASenderTransfer(reader, tokenID, senderAddr, senderAccount, now)
	return err
}

func evaluateDRWAReceiverTransfer(reader drwaStateReader, tokenID []byte, receiverAddr []byte, receiverAccount vmcommon.UserAccountHandler, now uint64) (bool, error) {
	regulated, policy, err := isDRWARegulatedToken(reader, tokenID, true)
	if err != nil || !regulated {
		return regulated, err
	}

	return evaluateDRWAReceiverTransferWithPolicy(reader, tokenID, policy, receiverAddr, receiverAccount, now)
}

func evaluateDRWAReceiverTransferWithPolicy(reader drwaStateReader, tokenID []byte, policy *drwaTokenPolicyView, receiverAddr []byte, receiverAccount vmcommon.UserAccountHandler, now uint64) (bool, error) {
	if policy == nil || !policy.DRWAEnabled {
		return false, nil
	}

	assetRecord, err := reader.GetAssetRecord(tokenID)
	if err != nil {
		return true, err
	}
	if isDRWAWindDownActive(policy, assetRecord) {
		recordDRWAGateMetric(drwaGateMetricDeniedWindDown)
		logDRWA.Warn(drwaLogReceiverDenied,
			"token", string(tokenID),
			"address", hex.EncodeToString(receiverAddr),
			"reason", errDRWAWindDownActive.Error(),
		)
		return true, errDRWAWindDownActive
	}

	holder, err := reader.GetHolderMirror(tokenID, receiverAddr, receiverAccount)
	if err != nil {
		return true, err
	}

	decision := validateDRWAReceiver(policy, holder, now)
	if !decision.Allowed {
		if m := drwaDenialMetric(decision.DenialCode); m != "" {
			recordDRWAGateMetric(m)
		}
		logDRWA.Warn(drwaLogReceiverDenied,
			"token", string(tokenID),
			"address", hex.EncodeToString(receiverAddr),
			"reason", decision.DenialCode.Error(),
		)
		return true, decision.DenialCode
	}

	return true, nil
}

func checkDRWAReceiverTransfer(reader drwaStateReader, tokenID []byte, receiverAddr []byte, receiverAccount vmcommon.UserAccountHandler, now uint64) error {
	_, err := evaluateDRWAReceiverTransfer(reader, tokenID, receiverAddr, receiverAccount, now)
	return err
}

func evaluateDRWAMetadataUpdate(reader drwaStateReader, tokenID []byte, callerAddr []byte, callerAccount vmcommon.UserAccountHandler) (bool, error) {
	regulated, policy, err := isDRWARegulatedToken(reader, tokenID, true)
	if err != nil || !regulated {
		return regulated, err
	}

	assetRecord, err := reader.GetAssetRecord(tokenID)
	if err != nil {
		return true, err
	}
	if isDRWAWindDownActive(policy, assetRecord) {
		recordDRWAGateMetric(drwaGateMetricDeniedWindDown)
		logDRWA.Warn(drwaLogMetadataDenied,
			"token", string(tokenID),
			"address", hex.EncodeToString(callerAddr),
			"reason", errDRWAWindDownActive.Error(),
		)
		return true, errDRWAWindDownActive
	}

	holder, err := reader.GetHolderMirror(tokenID, callerAddr, callerAccount)
	if err != nil {
		return true, err
	}

	// GL-4: Metadata updates must also enforce KYC/AML on the caller.
	// A non-compliant holder should not be able to modify token attributes.
	if holder == nil || !strings.EqualFold(holder.KYCStatus, "approved") {
		recordDRWAGateMetric(drwaGateMetricDeniedKYCSender)
		logDRWA.Warn(drwaLogMetadataDenied,
			"token", string(tokenID),
			"address", hex.EncodeToString(callerAddr),
			"reason", errDRWAKYCRequiredSender.Error(),
		)
		return true, errDRWAKYCRequiredSender
	}
	if !strings.EqualFold(holder.AMLStatus, "clear") && !strings.EqualFold(holder.AMLStatus, "approved") {
		recordDRWAGateMetric(drwaGateMetricDeniedAMLSender)
		logDRWA.Warn(drwaLogMetadataDenied,
			"token", string(tokenID),
			"address", hex.EncodeToString(callerAddr),
			"reason", errDRWAAMLBlockedSender.Error(),
		)
		return true, errDRWAAMLBlockedSender
	}

	auditorAuthorized := holder.AuditorAuthorized
	decision := validateDRWAMetadataUpdate(policy, auditorAuthorized)
	if !decision.Allowed {
		if m := drwaDenialMetric(decision.DenialCode); m != "" {
			recordDRWAGateMetric(m)
		}
		logDRWA.Warn(drwaLogMetadataDenied,
			"token", string(tokenID),
			"address", hex.EncodeToString(callerAddr),
			"reason", decision.DenialCode.Error(),
		)
		return true, decision.DenialCode
	}

	return true, nil
}

func checkDRWAMetadataUpdate(reader drwaStateReader, tokenID []byte, callerAddr []byte, callerAccount vmcommon.UserAccountHandler) error {
	_, err := evaluateDRWAMetadataUpdate(reader, tokenID, callerAddr, callerAccount)
	return err
}
