package builtInFunctions

import (
	"math"
	"testing"

	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
)

func TestValidateDRWAReceiverBranches(t *testing.T) {
	t.Parallel()

	if decision := validateDRWAReceiver(nil, nil, 0); !decision.Allowed {
		t.Fatalf("nil policy should allow receiver")
	}

	paused := validateDRWAReceiver(&drwaTokenPolicyView{DRWAEnabled: true, GlobalPause: true}, &drwaHolderMirrorView{}, 0)
	if paused.DenialCode != errDRWATokenPaused {
		t.Fatalf("expected paused denial, got %v", paused.DenialCode)
	}

	kyc := validateDRWAReceiver(&drwaTokenPolicyView{DRWAEnabled: true}, nil, 0)
	if kyc.DenialCode != errDRWAKYCRequiredReceiver {
		t.Fatalf("expected receiver kyc denial, got %v", kyc.DenialCode)
	}

	aml := validateDRWAReceiver(&drwaTokenPolicyView{DRWAEnabled: true}, &drwaHolderMirrorView{
		KYCStatus: "approved",
		AMLStatus: "blocked",
	}, 0)
	if aml.DenialCode != errDRWAAMLBlockedReceiver {
		t.Fatalf("expected aml denial, got %v", aml.DenialCode)
	}

	expired := validateDRWAReceiver(&drwaTokenPolicyView{DRWAEnabled: true}, &drwaHolderMirrorView{
		KYCStatus:   "approved",
		AMLStatus:   "approved",
		ExpiryRound: 10,
	}, 11)
	if expired.DenialCode != errDRWAAssetExpired {
		t.Fatalf("expected expiry denial, got %v", expired.DenialCode)
	}

	investorClass := validateDRWAReceiver(&drwaTokenPolicyView{
		DRWAEnabled:            true,
		AllowedInvestorClasses: map[string]bool{"QIB": true},
	}, &drwaHolderMirrorView{
		KYCStatus:     "approved",
		AMLStatus:     "approved",
		InvestorClass: "RETAIL",
	}, 0)
	if investorClass.DenialCode != errDRWAInvestorClass {
		t.Fatalf("expected investor class denial, got %v", investorClass.DenialCode)
	}

	jurisdiction := validateDRWAReceiver(&drwaTokenPolicyView{
		DRWAEnabled:          true,
		AllowedJurisdictions: map[string]bool{"US": true},
	}, &drwaHolderMirrorView{
		KYCStatus:        "approved",
		AMLStatus:        "approved",
		JurisdictionCode: "FR",
	}, 0)
	if jurisdiction.DenialCode != errDRWAJurisdiction {
		t.Fatalf("expected jurisdiction denial, got %v", jurisdiction.DenialCode)
	}

	allowed := validateDRWAReceiver(&drwaTokenPolicyView{
		DRWAEnabled:            true,
		AllowedInvestorClasses: map[string]bool{"qib": true},
		AllowedJurisdictions:   map[string]bool{"us": true},
	}, &drwaHolderMirrorView{
		KYCStatus:        "approved",
		AMLStatus:        "approved",
		InvestorClass:    "QIB",
		JurisdictionCode: "US",
	}, 0)
	if !allowed.Allowed {
		t.Fatalf("expected allowed receiver, got %v", allowed.DenialCode)
	}
}

func TestValidateDRWAHolderPolicyFreshnessDeniesStaleMirrors(t *testing.T) {
	t.Parallel()

	policy := &drwaTokenPolicyView{DRWAEnabled: true, TokenPolicyVersion: 3}
	holder := &drwaHolderMirrorView{
		KYCStatus:              "approved",
		AMLStatus:              "approved",
		PolicyVersionEvaluated: 2,
	}

	if decision := validateDRWASender(policy, holder, 100); decision.DenialCode != errDRWAPolicyNotSynced {
		t.Fatalf("expected sender policy-stale denial, got %v", decision.DenialCode)
	}
	if decision := validateDRWAReceiver(policy, holder, 100); decision.DenialCode != errDRWAPolicyNotSynced {
		t.Fatalf("expected receiver policy-stale denial, got %v", decision.DenialCode)
	}

	holder.PolicyVersionEvaluated = 3
	if decision := validateDRWASender(policy, holder, 100); !decision.Allowed {
		t.Fatalf("expected fresh sender holder mirror to pass, got %v", decision.DenialCode)
	}
	if decision := validateDRWAReceiver(policy, holder, 100); !decision.Allowed {
		t.Fatalf("expected fresh receiver holder mirror to pass, got %v", decision.DenialCode)
	}
}

// Tests for Travel Rule, Sanctions, Wind-down, and LockUntilRound enforcement.

func TestValidateDRWASenderDeniedWindDownActive(t *testing.T) {
	t.Parallel()
	policy := &drwaTokenPolicyView{DRWAEnabled: true, WindDownInitiated: true}
	holder := &drwaHolderMirrorView{KYCStatus: "approved", AMLStatus: "approved"}
	d := validateDRWASender(policy, holder, 100)
	if d.DenialCode != errDRWAWindDownActive {
		t.Fatalf("expected wind-down denial, got %v", d.DenialCode)
	}
}

func TestValidateDRWASenderDeniedTravelRuleRequired(t *testing.T) {
	t.Parallel()
	policy := &drwaTokenPolicyView{DRWAEnabled: true, TravelRuleRequired: true}
	holder := &drwaHolderMirrorView{
		KYCStatus:          "approved",
		AMLStatus:          "approved",
		TravelRuleAttested: false,
	}
	d := validateDRWASender(policy, holder, 100)
	if d.DenialCode != errDRWATravelRuleRequired {
		t.Fatalf("expected travel rule denial, got %v", d.DenialCode)
	}
}

func TestValidateDRWASenderAllowedTravelRuleAttested(t *testing.T) {
	t.Parallel()
	policy := &drwaTokenPolicyView{DRWAEnabled: true, TravelRuleRequired: true}
	holder := &drwaHolderMirrorView{
		KYCStatus:          "approved",
		AMLStatus:          "approved",
		TravelRuleAttested: true,
	}
	d := validateDRWASender(policy, holder, 100)
	if !d.Allowed {
		t.Fatalf("expected allowed with travel rule attested, got %v", d.DenialCode)
	}
}

func TestValidateDRWASenderDeniedSanctionsMatch(t *testing.T) {
	t.Parallel()
	policy := &drwaTokenPolicyView{DRWAEnabled: true, SanctionsScreeningEnabled: true}
	holder := &drwaHolderMirrorView{
		KYCStatus:        "approved",
		AMLStatus:        "approved",
		SanctionsCleared: false,
	}
	d := validateDRWASender(policy, holder, 100)
	if d.DenialCode != errDRWASanctionsMatch {
		t.Fatalf("expected sanctions denial, got %v", d.DenialCode)
	}
}

func TestValidateDRWASenderAllowedSanctionsCleared(t *testing.T) {
	t.Parallel()
	policy := &drwaTokenPolicyView{DRWAEnabled: true, SanctionsScreeningEnabled: true}
	holder := &drwaHolderMirrorView{
		KYCStatus:        "approved",
		AMLStatus:        "approved",
		SanctionsCleared: true,
	}
	d := validateDRWASender(policy, holder, 100)
	if !d.Allowed {
		t.Fatalf("expected allowed with sanctions cleared, got %v", d.DenialCode)
	}
}

func TestValidateDRWASenderDeniedLockUntilRound(t *testing.T) {
	t.Parallel()
	policy := &drwaTokenPolicyView{DRWAEnabled: true}
	holder := &drwaHolderMirrorView{
		KYCStatus:      "approved",
		AMLStatus:      "approved",
		LockUntilRound: 500,
	}
	// Current round 100 < lock until 500 — should deny
	d := validateDRWASender(policy, holder, 100)
	if d.DenialCode != errDRWATransferLocked {
		t.Fatalf("expected transfer locked (SEC Rule 144), got %v", d.DenialCode)
	}
}

func TestValidateDRWASenderAllowedLockUntilRoundExpired(t *testing.T) {
	t.Parallel()
	policy := &drwaTokenPolicyView{DRWAEnabled: true}
	holder := &drwaHolderMirrorView{
		KYCStatus:      "approved",
		AMLStatus:      "approved",
		LockUntilRound: 500,
	}
	// Current round 600 > lock until 500 — should allow
	d := validateDRWASender(policy, holder, 600)
	if !d.Allowed {
		t.Fatalf("expected allowed after lock period expired, got %v", d.DenialCode)
	}
}

func TestValidateDRWAReceiverDeniedWindDownActive(t *testing.T) {
	t.Parallel()
	policy := &drwaTokenPolicyView{DRWAEnabled: true, WindDownInitiated: true}
	holder := &drwaHolderMirrorView{KYCStatus: "approved", AMLStatus: "approved"}
	d := validateDRWAReceiver(policy, holder, 100)
	if d.DenialCode != errDRWAWindDownActive {
		t.Fatalf("expected wind-down denial on receiver, got %v", d.DenialCode)
	}
}

func TestValidateDRWAReceiverDeniedTravelRuleRequired(t *testing.T) {
	t.Parallel()
	policy := &drwaTokenPolicyView{DRWAEnabled: true, TravelRuleRequired: true}
	holder := &drwaHolderMirrorView{
		KYCStatus:          "approved",
		AMLStatus:          "approved",
		TravelRuleAttested: false,
	}
	d := validateDRWAReceiver(policy, holder, 100)
	if d.DenialCode != errDRWATravelRuleRequired {
		t.Fatalf("expected travel rule denial on receiver, got %v", d.DenialCode)
	}
}

func TestValidateDRWAReceiverDeniedSanctionsMatch(t *testing.T) {
	t.Parallel()
	policy := &drwaTokenPolicyView{DRWAEnabled: true, SanctionsScreeningEnabled: true}
	holder := &drwaHolderMirrorView{
		KYCStatus:        "approved",
		AMLStatus:        "approved",
		SanctionsCleared: false,
	}
	d := validateDRWAReceiver(policy, holder, 100)
	if d.DenialCode != errDRWASanctionsMatch {
		t.Fatalf("expected sanctions denial on receiver, got %v", d.DenialCode)
	}
}

func TestValidateDRWAMetadataUpdateBranches(t *testing.T) {
	t.Parallel()

	if decision := validateDRWAMetadataUpdate(nil, false); !decision.Allowed {
		t.Fatalf("nil policy should allow metadata update")
	}

	if decision := validateDRWAMetadataUpdate(&drwaTokenPolicyView{DRWAEnabled: true}, false); !decision.Allowed {
		t.Fatalf("metadata protection disabled should allow")
	}

	if decision := validateDRWAMetadataUpdate(&drwaTokenPolicyView{
		DRWAEnabled:               true,
		MetadataProtectionEnabled: true,
		StrictAuditorMode:         false,
	}, false); !decision.Allowed {
		t.Fatalf("non-strict metadata protection should allow")
	}

	denied := validateDRWAMetadataUpdate(&drwaTokenPolicyView{
		DRWAEnabled:               true,
		MetadataProtectionEnabled: true,
		StrictAuditorMode:         true,
	}, false)
	if denied.DenialCode != errDRWAAuditorRequired {
		t.Fatalf("expected auditor required denial, got %v", denied.DenialCode)
	}

	allowed := validateDRWAMetadataUpdate(&drwaTokenPolicyView{
		DRWAEnabled:               true,
		MetadataProtectionEnabled: true,
		StrictAuditorMode:         true,
	}, true)
	if !allowed.Allowed {
		t.Fatalf("expected auditor-authorized metadata update to pass")
	}
}

type stubDRWAStateReader struct {
	policy      *drwaTokenPolicyView
	holder      *drwaHolderMirrorView
	assetRecord *drwaAssetRecordView
	active      bool
}

func (s *stubDRWAStateReader) GetTokenPolicy(_ []byte) (*drwaTokenPolicyView, error) {
	return s.policy, nil
}

func (s *stubDRWAStateReader) GetHolderMirror(_ []byte, _ []byte, _ vmcommon.UserAccountHandler) (*drwaHolderMirrorView, error) {
	return s.holder, nil
}

func (s *stubDRWAStateReader) GetHolderProfile(_ []byte) (*drwaHolderProfileView, error) {
	return nil, nil
}

func (s *stubDRWAStateReader) GetHolderAuditorAuthorization(_ []byte, _ []byte) (*drwaHolderAuditorAuthorizationView, error) {
	return nil, nil
}

func (s *stubDRWAStateReader) GetAssetRecord(_ []byte) (*drwaAssetRecordView, error) {
	return s.assetRecord, nil
}

func (s *stubDRWAStateReader) IsDRWAActive(_ []byte) (bool, error) {
	return s.active, nil
}

func TestEvaluateDRWASenderTransferWithPolicyDeniesAssetRecordWindDown(t *testing.T) {
	t.Parallel()

	reader := &stubDRWAStateReader{
		policy: &drwaTokenPolicyView{DRWAEnabled: true},
		holder: &drwaHolderMirrorView{KYCStatus: "approved", AMLStatus: "approved"},
		assetRecord: &drwaAssetRecordView{
			WindDownInitiated: true,
		},
	}

	regulated, err := evaluateDRWASenderTransferWithPolicy(reader, []byte("HOTEL-1234"), reader.policy, []byte("sender"), nil, 100)
	if !regulated {
		t.Fatalf("expected regulated token")
	}
	if err != errDRWAWindDownActive {
		t.Fatalf("expected wind-down denial, got %v", err)
	}
}

func TestEvaluateDRWAReceiverTransferWithPolicyDeniesAssetRecordWindDown(t *testing.T) {
	t.Parallel()

	reader := &stubDRWAStateReader{
		policy: &drwaTokenPolicyView{DRWAEnabled: true},
		holder: &drwaHolderMirrorView{KYCStatus: "approved", AMLStatus: "approved"},
		assetRecord: &drwaAssetRecordView{
			WindDownInitiated: true,
		},
	}

	regulated, err := evaluateDRWAReceiverTransferWithPolicy(reader, []byte("HOTEL-1234"), reader.policy, []byte("receiver"), nil, 100)
	if !regulated {
		t.Fatalf("expected regulated token")
	}
	if err != errDRWAWindDownActive {
		t.Fatalf("expected wind-down denial, got %v", err)
	}
}

func TestEvaluateDRWAMetadataUpdateDeniesAssetRecordWindDown(t *testing.T) {
	t.Parallel()

	reader := &stubDRWAStateReader{
		policy: &drwaTokenPolicyView{DRWAEnabled: true},
		holder: &drwaHolderMirrorView{
			KYCStatus:         "approved",
			AMLStatus:         "approved",
			AuditorAuthorized: true,
		},
		assetRecord: &drwaAssetRecordView{
			WindDownInitiated: true,
		},
	}

	regulated, err := evaluateDRWAMetadataUpdate(reader, []byte("HOTEL-1234"), []byte("caller"), nil)
	if !regulated {
		t.Fatalf("expected regulated token")
	}
	if err != errDRWAWindDownActive {
		t.Fatalf("expected wind-down denial, got %v", err)
	}
}

func TestEvaluateDRWAMetadataUpdateDeniesStalePolicyMirror(t *testing.T) {
	t.Parallel()

	reader := &stubDRWAStateReader{
		policy: &drwaTokenPolicyView{
			DRWAEnabled:               true,
			MetadataProtectionEnabled: true,
			TokenPolicyVersion:        4,
		},
		holder: &drwaHolderMirrorView{
			KYCStatus:              "approved",
			AMLStatus:              "approved",
			AuditorAuthorized:      true,
			PolicyVersionEvaluated: 3,
		},
	}

	regulated, err := evaluateDRWAMetadataUpdate(reader, []byte("HOTEL-1234"), []byte("caller"), nil)
	if !regulated {
		t.Fatalf("expected regulated token")
	}
	if err != errDRWAPolicyNotSynced {
		t.Fatalf("expected stale policy denial, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// F2 (closes N1): LockUntilRound deny-by-default when round is unknown
// ---------------------------------------------------------------------------

// TestValidateDRWASenderDeniesLockUntilRoundWhenRoundZero is the regression
// guard for N1. Before F2, the LockUntilRound check had an explicit `now > 0`
// guard that silently bypassed SEC Rule 144 enforcement when the blockchain
// hook returned a zero round. The expiry checks already deny-by-default in
// that case; LockUntilRound must do the same to maintain consistent
// fail-closed semantics for time-based restrictions.
func TestValidateDRWASenderDeniesLockUntilRoundWhenRoundZero(t *testing.T) {
	t.Parallel()
	policy := &drwaTokenPolicyView{DRWAEnabled: true}
	holder := &drwaHolderMirrorView{
		KYCStatus:      "approved",
		AMLStatus:      "approved",
		LockUntilRound: 1000,
	}
	d := validateDRWASender(policy, holder, 0)
	if d.DenialCode != errDRWATransferLocked {
		t.Fatalf("expected transfer locked deny-by-default at round=0, got %v", d.DenialCode)
	}
}

// TestValidateDRWASenderRoundZeroAllowsHolderWithoutTimeBasedRestrictions
// asserts the F2 fix is scoped: a holder with no expiry and no LockUntilRound
// continues to be allowed at round=0. This preserves the legitimate test path
// that uses round=0 as a "round-irrelevant" sentinel.
func TestValidateDRWASenderRoundZeroAllowsHolderWithoutTimeBasedRestrictions(t *testing.T) {
	t.Parallel()
	policy := &drwaTokenPolicyView{DRWAEnabled: true}
	holder := &drwaHolderMirrorView{
		KYCStatus: "approved",
		AMLStatus: "approved",
	}
	d := validateDRWASender(policy, holder, 0)
	if !d.Allowed {
		t.Fatalf("expected allow for holder without time-based restrictions at round=0, got %v", d.DenialCode)
	}
}

// TestValidateDRWASenderLockUntilRoundStillEnforcedDuringNormalOperation is a
// regression guard ensuring the F2 fix did not change behavior in the normal
// path. With round > 0 and round < LockUntilRound, the existing check fires
// and the holder is denied with the same error code.
func TestValidateDRWASenderLockUntilRoundStillEnforcedDuringNormalOperation(t *testing.T) {
	t.Parallel()
	policy := &drwaTokenPolicyView{DRWAEnabled: true}
	holder := &drwaHolderMirrorView{
		KYCStatus:      "approved",
		AMLStatus:      "approved",
		LockUntilRound: 1000,
	}
	d := validateDRWASender(policy, holder, 500)
	if d.DenialCode != errDRWATransferLocked {
		t.Fatalf("expected transfer locked at round=500 < lock=1000, got %v", d.DenialCode)
	}
}

func TestValidateDRWASenderDeniedLockUntilRoundNearUint64Boundary(t *testing.T) {
	t.Parallel()
	policy := &drwaTokenPolicyView{DRWAEnabled: true}
	holder := &drwaHolderMirrorView{
		KYCStatus:      "approved",
		AMLStatus:      "approved",
		LockUntilRound: math.MaxUint64,
	}

	d := validateDRWASender(policy, holder, math.MaxUint64-1)
	if d.DenialCode != errDRWATransferLocked {
		t.Fatalf("expected transfer locked near uint64 boundary, got %v", d.DenialCode)
	}
}

func TestValidateDRWASenderAllowedLockUntilRoundAtUint64Boundary(t *testing.T) {
	t.Parallel()
	policy := &drwaTokenPolicyView{DRWAEnabled: true}
	holder := &drwaHolderMirrorView{
		KYCStatus:      "approved",
		AMLStatus:      "approved",
		LockUntilRound: math.MaxUint64 - 1,
	}

	d := validateDRWASender(policy, holder, math.MaxUint64)
	if !d.Allowed {
		t.Fatalf("expected allowed after uint64-boundary lock expired, got %v", d.DenialCode)
	}
}

func TestValidateDRWAMetadataUpdateDeniedWindDownActive(t *testing.T) {
	t.Parallel()

	decision := validateDRWAMetadataUpdate(&drwaTokenPolicyView{
		DRWAEnabled:               true,
		WindDownInitiated:         true,
		MetadataProtectionEnabled: true,
	}, true)
	if decision.DenialCode != errDRWAWindDownActive {
		t.Fatalf("expected wind-down denial for metadata update, got %v", decision.DenialCode)
	}
}
