package builtInFunctions

import (
	"encoding/binary"
	"encoding/json"
	"math"
	"testing"

	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/multiversx/mx-chain-vm-common-go/mock"
	"github.com/stretchr/testify/require"
)

// nonUserAccountStub satisfies vmcommon.AccountHandler but NOT
// vmcommon.UserAccountHandler. Used to exercise the type-assertion
// failure path in loadUserAccount without importing mx-chain-go
// (which would create a circular dependency).
type nonUserAccountStub struct{}

func (s *nonUserAccountStub) AddressBytes() []byte   { return []byte("stub") }
func (s *nonUserAccountStub) IncreaseNonce(_ uint64) { /* no-op stub */ }
func (s *nonUserAccountStub) GetNonce() uint64       { return 0 }
func (s *nonUserAccountStub) IsInterfaceNil() bool   { return false }

func TestNewDRWAAccountsReaderRejectsNilAccounts(t *testing.T) {
	t.Parallel()

	reader, err := newDRWAAccountsReader(nil)
	require.Nil(t, reader)
	require.EqualError(t, err, "nil DRWA accounts adapter")
}

func TestDRWAAccountsReaderLoadUserAccountUsesCurrentAccount(t *testing.T) {
	t.Parallel()

	current := mock.NewUserAccount([]byte("holder"))
	reader, err := newDRWAAccountsReader(&mock.AccountsStub{
		LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
			t.Fatalf("load should not be called for current account")
			return nil, nil
		},
	})
	require.NoError(t, err)

	loaded, err := reader.loadUserAccount([]byte("holder"), current)
	require.NoError(t, err)
	require.Same(t, current, loaded)
	require.False(t, reader.IsInterfaceNil())

	var nilReader *drwaAccountsReader
	require.True(t, nilReader.IsInterfaceNil())
}

func TestDRWAAccountsReaderLoadUserAccountRejectsWrongType(t *testing.T) {
	t.Parallel()

	reader, err := newDRWAAccountsReader(&mock.AccountsStub{
		LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
			return &nonUserAccountStub{}, nil
		},
	})
	require.NoError(t, err)

	loaded, err := reader.loadUserAccount([]byte("holder"), nil)
	require.Nil(t, loaded)
	require.ErrorIs(t, err, ErrWrongTypeAssertion)
}

func TestDecodeDRWAStoredJSONUsesWrappedBody(t *testing.T) {
	t.Parallel()

	wrapped, err := json.Marshal(&drwaStoredValue{
		Version: 3,
		Body:    []byte(`{"drwa_enabled":true}`),
	})
	require.NoError(t, err)

	view := &drwaTokenPolicyView{}
	require.NoError(t, decodeDRWAStoredJSON(wrapped, view))
	require.True(t, view.DRWAEnabled)
}

func TestDecodeDRWAStoredJSONPolicyAndHolderExtensionFields(t *testing.T) {
	t.Parallel()

	policyWrapped, err := json.Marshal(&drwaStoredValue{
		Version: 7,
		Body: []byte(`{"drwa_enabled":true,"token_policy_version":7,"travel_rule_required":true,` +
			`"sanctions_screening_enabled":true}`),
	})
	require.NoError(t, err)

	policy := &drwaTokenPolicyView{}
	require.NoError(t, decodeDRWAStoredJSON(policyWrapped, policy))
	require.True(t, policy.DRWAEnabled)
	require.Equal(t, uint64(7), policy.TokenPolicyVersion)
	require.True(t, policy.TravelRuleRequired)
	require.True(t, policy.SanctionsScreeningEnabled)

	holderWrapped, err := json.Marshal(&drwaStoredValue{
		Version: 9,
		Body: []byte(`{"kyc_status":"approved","aml_status":"clear","investor_class":"professional",` +
			`"jurisdiction_code":"SG","expiry_round":0,"transfer_locked":false,"receive_locked":false,` +
			`"auditor_authorized":false,"policy_version_evaluated":7,"lock_until_round":0,` +
			`"travel_rule_attested":true,"sanctions_cleared":true,` +
			`"sanctions_screening_cid":"bafy-screening-1","ubo_parent_entity":"issuer:parent",` +
			`"ownership_pct":2500}`),
	})
	require.NoError(t, err)

	holder := &drwaHolderMirrorView{}
	require.NoError(t, decodeDRWAStoredJSON(holderWrapped, holder))
	require.Equal(t, "approved", holder.KYCStatus)
	require.Equal(t, "clear", holder.AMLStatus)
	require.Equal(t, "professional", holder.InvestorClass)
	require.Equal(t, "SG", holder.JurisdictionCode)
	require.Equal(t, uint64(7), holder.PolicyVersionEvaluated)
	require.Equal(t, uint64(9), holder.storedVersion)
	require.True(t, holder.TravelRuleAttested)
	require.True(t, holder.SanctionsCleared)
	require.Equal(t, "bafy-screening-1", holder.SanctionsScreeningCid)
	require.Equal(t, "issuer:parent", holder.UboParentEntity)
	require.Equal(t, uint32(2500), holder.OwnershipPct)

	decision := validateDRWASender(policy, holder, 100)
	require.True(t, decision.Allowed)
	require.NoError(t, decision.DenialCode)
}

func TestDecodeDRWAStoredJSONRejectsMalformedWrapperInsteadOfFallingBackToRawBody(t *testing.T) {
	t.Parallel()

	view := &drwaTokenPolicyView{}
	require.Error(t, decodeDRWAStoredJSON([]byte(`{"drwa_enabled":true}`), view))
}

func TestDecodeDRWABodyBinaryProfileAndAuthorization(t *testing.T) {
	t.Parallel()

	profilePayload := make([]byte, 0, 64)
	profilePayload = append(profilePayload, make([]byte, 8)...)
	profilePayload = appendLenPrefixed(profilePayload, []byte("approved"))
	profilePayload = appendLenPrefixed(profilePayload, []byte("approved"))
	profilePayload = appendLenPrefixed(profilePayload, []byte("accredited"))
	profilePayload = appendLenPrefixed(profilePayload, []byte("SG"))
	expiry := make([]byte, 8)
	binary.BigEndian.PutUint64(expiry, 42)
	profilePayload = append(profilePayload, expiry...)

	profile := &drwaHolderProfileView{}
	require.NoError(t, decodeDRWABody(profilePayload, profile))
	require.Equal(t, "approved", profile.KYCStatus)
	require.Equal(t, "approved", profile.AMLStatus)
	require.Equal(t, "accredited", profile.InvestorClass)
	require.Equal(t, "SG", profile.JurisdictionCode)
	require.Equal(t, uint64(42), profile.ExpiryRound)

	authPayload := make([]byte, 9)
	authPayload[8] = 1
	auth := &drwaHolderAuditorAuthorizationView{}
	require.NoError(t, decodeDRWABody(authPayload, auth))
	require.True(t, auth.AuditorAuthorized)

	// Non-zero bytes in positions 0-7 must be ignored; only byte 8 determines authorization.
	authPayloadNonZeroPrefix := make([]byte, 9)
	authPayloadNonZeroPrefix[0] = 0xFF
	authPayloadNonZeroPrefix[1] = 0xAB
	authPayloadNonZeroPrefix[2] = 0xCD
	authPayloadNonZeroPrefix[3] = 0xEF
	authPayloadNonZeroPrefix[4] = 0x12
	authPayloadNonZeroPrefix[5] = 0x34
	authPayloadNonZeroPrefix[6] = 0x56
	authPayloadNonZeroPrefix[7] = 0x78
	authPayloadNonZeroPrefix[8] = 1 // authorized
	authNonZero := &drwaHolderAuditorAuthorizationView{}
	require.NoError(t, decodeDRWABody(authPayloadNonZeroPrefix, authNonZero))
	require.True(t, authNonZero.AuditorAuthorized, "non-zero prefix bytes 0-7 must be ignored")

	// Same prefix but byte 8 = 0 → not authorized
	authPayloadNonZeroPrefix[8] = 0
	authNotAuthorized := &drwaHolderAuditorAuthorizationView{}
	require.NoError(t, decodeDRWABody(authPayloadNonZeroPrefix, authNotAuthorized))
	require.False(t, authNotAuthorized.AuditorAuthorized, "byte 8 = 0 must yield unauthorized regardless of prefix")
}

func TestDecodeDRWABodyRejectsBrokenJSONWithoutBinaryFallback(t *testing.T) {
	t.Parallel()

	tokenPolicy := &drwaTokenPolicyView{}
	err := decodeDRWABody([]byte("{not-json"), tokenPolicy)
	require.Error(t, err)
}

func TestDecodeDRWABodyDoesNotTreatAccidentallyValidJSONScalarAsStructuredState(t *testing.T) {
	t.Parallel()

	holder := &drwaHolderMirrorView{}
	err := decodeDRWABody([]byte("0"), holder)
	require.Error(t, err)
}

func TestDecodeDRWABodyFallsBackToJSONForUnknownDestination(t *testing.T) {
	t.Parallel()

	destination := &struct {
		Value string `json:"value"`
	}{}

	require.NoError(t, decodeDRWABody([]byte(`{"value":"ok"}`), destination))
	require.Equal(t, "ok", destination.Value)
}

// NOTE: This test must NOT use t.Parallel() — it mutates shared package-level metric counters.
func TestDecodeDRWAStoredJSONRecordsFailureMetricsByType(t *testing.T) {
	resetDRWAGateMetrics()

	require.Error(t, decodeDRWAStoredJSON([]byte("{not-json"), &drwaTokenPolicyView{}))
	require.Error(t, decodeDRWAStoredJSON([]byte{}, &drwaHolderMirrorView{}))
	require.Error(t, decodeDRWAStoredJSON([]byte{0, 0, 0, 0}, &drwaHolderProfileView{}))

	snapshot := SnapshotDRWAGateMetrics()
	require.Equal(t, uint64(3), snapshot[drwaGateMetricDecodeFailure])
	require.Equal(t, uint64(1), snapshot[drwaGateMetricDecodeFailureJSON])
	require.Equal(t, uint64(1), snapshot[drwaGateMetricDecodeFailureMissing])
	require.Equal(t, uint64(1), snapshot[drwaGateMetricDecodeFailureBinary])
}

func TestDecodeDRWABinaryTokenPolicyRejectsShortPayload(t *testing.T) {
	t.Parallel()

	view := &drwaTokenPolicyView{}
	require.Error(t, decodeDRWABinaryTokenPolicy(make([]byte, 11), view))
}

func TestDecodeDRWABinaryTokenPolicyAcceptsCanonicalBooleanOnlyPayload(t *testing.T) {
	t.Parallel()

	view := &drwaTokenPolicyView{}
	payload := make([]byte, drwaBinaryTokenPolicyMinSize)
	payload[0] = 1
	payload[1] = 1
	payload[2] = 1
	payload[3] = 1

	require.NoError(t, decodeDRWABinaryTokenPolicy(payload, view))
	require.True(t, view.DRWAEnabled)
	require.True(t, view.GlobalPause)
	require.True(t, view.StrictAuditorMode)
	require.True(t, view.MetadataProtectionEnabled)
	require.Nil(t, view.AllowedInvestorClasses)
	require.Nil(t, view.AllowedJurisdictions)
}

func TestDecodeDRWABinaryHolderMirrorRejectsShortPayload(t *testing.T) {
	t.Parallel()

	view := &drwaHolderMirrorView{}
	require.Error(t, decodeDRWABinaryHolderMirror(make([]byte, 13), view))
}

func TestReadDRWABinaryFieldRejectsShortBodies(t *testing.T) {
	t.Parallel()

	_, _, err := readDRWABinaryField([]byte{0, 0, 0}, 0)
	require.Error(t, err)

	profile := &drwaHolderProfileView{}
	err = decodeDRWABinaryHolderProfile(make([]byte, 8), profile)
	require.Error(t, err)

	auth := &drwaHolderAuditorAuthorizationView{}
	err = decodeDRWABinaryHolderAuditorAuthorization(make([]byte, 8), auth)
	require.Error(t, err)
}

func TestDecodeDRWABinaryHolderMirrorRejectsFieldAndTrailerCorruption(t *testing.T) {
	t.Parallel()

	prefixOnly := make([]byte, 8)
	err := decodeDRWABinaryHolderMirror(prefixOnly, &drwaHolderMirrorView{})
	require.Error(t, err)

	invalidFieldBody := make([]byte, 12)
	binary.BigEndian.PutUint32(invalidFieldBody[8:12], 4)
	err = decodeDRWABinaryHolderMirror(invalidFieldBody, &drwaHolderMirrorView{})
	require.Error(t, err)

	shortTrailer := make([]byte, 0, 40)
	shortTrailer = append(shortTrailer, make([]byte, 8)...)
	shortTrailer = appendLenPrefixed(shortTrailer, []byte("approved"))
	shortTrailer = appendLenPrefixed(shortTrailer, []byte("approved"))
	shortTrailer = appendLenPrefixed(shortTrailer, []byte("qib"))
	shortTrailer = appendLenPrefixed(shortTrailer, []byte("US"))
	shortTrailer = append(shortTrailer, make([]byte, 10)...)
	err = decodeDRWABinaryHolderMirror(shortTrailer, &drwaHolderMirrorView{})
	require.Error(t, err)
}

func TestDecodeDRWABinaryHolderProfileRejectsFieldAndTrailerCorruption(t *testing.T) {
	t.Parallel()

	prefixOnly := make([]byte, 8)
	err := decodeDRWABinaryHolderProfile(prefixOnly, &drwaHolderProfileView{})
	require.Error(t, err)

	invalidFieldBody := make([]byte, 12)
	binary.BigEndian.PutUint32(invalidFieldBody[8:12], 4)
	err = decodeDRWABinaryHolderProfile(invalidFieldBody, &drwaHolderProfileView{})
	require.Error(t, err)

	shortTrailer := make([]byte, 0, 40)
	shortTrailer = append(shortTrailer, make([]byte, 8)...)
	shortTrailer = appendLenPrefixed(shortTrailer, []byte("approved"))
	shortTrailer = appendLenPrefixed(shortTrailer, []byte("approved"))
	shortTrailer = appendLenPrefixed(shortTrailer, []byte("qib"))
	shortTrailer = appendLenPrefixed(shortTrailer, []byte("US"))
	shortTrailer = append(shortTrailer, make([]byte, 7)...)
	err = decodeDRWABinaryHolderProfile(shortTrailer, &drwaHolderProfileView{})
	require.Error(t, err)

	trailingBytes := make([]byte, 0, 48)
	trailingBytes = append(trailingBytes, make([]byte, 8)...)
	trailingBytes = appendLenPrefixed(trailingBytes, []byte("approved"))
	trailingBytes = appendLenPrefixed(trailingBytes, []byte("approved"))
	trailingBytes = appendLenPrefixed(trailingBytes, []byte("qib"))
	trailingBytes = appendLenPrefixed(trailingBytes, []byte("US"))
	trailingBytes = append(trailingBytes, make([]byte, 8)...)
	trailingBytes = append(trailingBytes, 0xAA)
	err = decodeDRWABinaryHolderProfile(trailingBytes, &drwaHolderProfileView{})
	require.Error(t, err)
}

func TestIsDRWAEnforcementEnabledAndReadGasCost(t *testing.T) {
	t.Parallel()

	require.False(t, isDRWAEnforcementEnabled(nil))
	require.True(t, isDRWAEnforcementEnabled(drwaEnabledEpochsHandler()))
	require.Equal(t, uint64(0), computeDRWAReadGasCost(vmcommon.BaseOperationCost{}, 7, 0))
	require.Equal(t, uint64(drwaMinReadGasCost), computeDRWAReadGasCost(vmcommon.BaseOperationCost{}, 0, 3))
	// With drwaReadGasUnits=10: 3 reads * 7 fallbackCost * 10 = 210
	require.Equal(t, uint64(210), computeDRWAReadGasCost(vmcommon.BaseOperationCost{StorePerByte: 5}, 7, 3))
	require.Equal(t, uint64(210), computeDRWAReadGasCost(vmcommon.BaseOperationCost{}, 7, 3))
}

func TestComputeDRWAReadGasCostOverflow(t *testing.T) {
	t.Parallel()

	// When fallbackCost * reads * drwaReadGasUnits would overflow uint64, should return MaxUint64.
	result := computeDRWAReadGasCost(vmcommon.BaseOperationCost{}, math.MaxUint64, 2)
	require.Equal(t, uint64(math.MaxUint64), result)

	// Normal case should compute correctly: fallbackCost=100, reads=3, drwaReadGasUnits=10 => 3000
	result = computeDRWAReadGasCost(vmcommon.BaseOperationCost{}, 100, 3)
	require.Equal(t, uint64(100*3*drwaReadGasUnitsAtomic.Load()), result)
}

func TestReadDRWABinaryFieldRejectsOversizedLength(t *testing.T) {
	t.Parallel()

	// Construct a payload where the 4-byte length prefix exceeds 64*1024 (drwaSyncMaxFieldBytes cap).
	oversizedLength := uint32(64*1024 + 1)
	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload, oversizedLength)

	_, _, err := readDRWABinaryField(payload, 0)
	require.ErrorIs(t, err, errDRWABinaryFieldOverflow)
}

func TestDecodeDRWAStoredJSON_AuditorAuthSetsStoredVersion(t *testing.T) {
	t.Parallel()

	body := make([]byte, 9)
	body[8] = 1 // auditor authorized
	wrapped, _ := json.Marshal(&drwaStoredValue{Version: 7, Body: body})

	view := &drwaHolderAuditorAuthorizationView{}
	err := decodeDRWAStoredJSON(wrapped, view)
	require.NoError(t, err)
	require.Equal(t, uint64(7), view.storedVersion)
	require.True(t, view.AuditorAuthorized)
}

func appendLenPrefixed(buffer []byte, value []byte) []byte {
	length := make([]byte, 4)
	binary.BigEndian.PutUint32(length, uint32(len(value)))
	buffer = append(buffer, length...)
	buffer = append(buffer, value...)
	return buffer
}
