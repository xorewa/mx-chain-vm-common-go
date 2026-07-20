package builtInFunctions

// drwa_coverage_test.go — G-01, G-03, G-08, G-10: Additional tests to raise
// coverage to >=90% for drwa.go in mx-chain-vm-common-go/builtInFunctions.

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/multiversx/mx-chain-vm-common-go/mock"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// G-03: Test now==0 expiry deny-by-default in validateDRWASender
// ---------------------------------------------------------------------------

func TestValidateDRWASender_NowZeroWithExpiryDenies(t *testing.T) {
	t.Parallel()

	policy := &drwaTokenPolicyView{DRWAEnabled: true}

	// ExpiryRound set, now==0 → deny
	holder := &drwaHolderMirrorView{
		KYCStatus:   "approved",
		AMLStatus:   "approved",
		ExpiryRound: 100,
	}
	d := validateDRWASender(policy, holder, 0)
	require.Equal(t, errDRWAAssetExpired, d.DenialCode,
		"now==0 with ExpiryRound set must deny by default")

	// IdentityExpiryRound set, now==0 → deny
	holder2 := &drwaHolderMirrorView{
		KYCStatus:           "approved",
		AMLStatus:           "approved",
		IdentityExpiryRound: 50,
	}
	d = validateDRWASender(policy, holder2, 0)
	require.Equal(t, errDRWAAssetExpired, d.DenialCode,
		"now==0 with IdentityExpiryRound set must deny by default")

	// Both set, now==0 → deny
	holder3 := &drwaHolderMirrorView{
		KYCStatus:           "approved",
		AMLStatus:           "approved",
		ExpiryRound:         100,
		IdentityExpiryRound: 50,
	}
	d = validateDRWASender(policy, holder3, 0)
	require.Equal(t, errDRWAAssetExpired, d.DenialCode,
		"now==0 with both expiry rounds set must deny by default")

	// No expiry set, now==0 → allow
	holder4 := &drwaHolderMirrorView{
		KYCStatus: "approved",
		AMLStatus: "approved",
	}
	d = validateDRWASender(policy, holder4, 0)
	require.True(t, d.Allowed, "now==0 with no expiry should allow")
}

func TestValidateDRWAReceiver_NowZeroWithExpiryDenies(t *testing.T) {
	t.Parallel()

	policy := &drwaTokenPolicyView{DRWAEnabled: true}

	holder := &drwaHolderMirrorView{
		KYCStatus:   "approved",
		AMLStatus:   "approved",
		ExpiryRound: 100,
	}
	d := validateDRWAReceiver(policy, holder, 0)
	require.Equal(t, errDRWAAssetExpired, d.DenialCode,
		"receiver: now==0 with ExpiryRound set must deny by default")

	holder2 := &drwaHolderMirrorView{
		KYCStatus:           "approved",
		AMLStatus:           "approved",
		IdentityExpiryRound: 50,
	}
	d = validateDRWAReceiver(policy, holder2, 0)
	require.Equal(t, errDRWAAssetExpired, d.DenialCode,
		"receiver: now==0 with IdentityExpiryRound set must deny by default")
}

// ---------------------------------------------------------------------------
// G-08: Verify named constants are used (compile-time) and have correct values
// ---------------------------------------------------------------------------

func TestDRWABinaryDecoderNamedConstants(t *testing.T) {
	t.Parallel()

	require.Equal(t, 12, drwaBinaryTokenPolicyMinSize)
	require.Equal(t, 8, drwaBinaryHolderPayloadMinSize)
	require.Equal(t, 11, drwaBinaryHolderTrailerMinSize)
	require.Equal(t, 8, drwaBinaryProfilePayloadMinSize)
	require.Equal(t, 9, drwaBinaryAuditorAuthPayloadMinSize)
}

// ---------------------------------------------------------------------------
// G-01: Coverage for BuildDRWA*Key nil-return paths (empty input)
// ---------------------------------------------------------------------------

func TestBuildDRWAKeyFunctionsRejectEmptyInput(t *testing.T) {
	t.Parallel()

	require.Nil(t, BuildDRWATokenPolicyKey(nil))
	require.Nil(t, BuildDRWATokenPolicyKey([]byte{}))
	require.Nil(t, BuildDRWAHolderMirrorKey(nil, []byte("addr")))
	require.Nil(t, BuildDRWAHolderMirrorKey([]byte("token"), nil))
	require.Nil(t, BuildDRWAHolderMirrorKey([]byte("token"), []byte{}))
	require.Nil(t, BuildDRWAHolderProfileKey(nil))
	require.Nil(t, BuildDRWAHolderProfileKey([]byte{}))
	require.Nil(t, BuildDRWAHolderAuditorAuthorizationKey(nil, []byte("addr")))
	require.Nil(t, BuildDRWAHolderAuditorAuthorizationKey([]byte("token"), nil))
	require.Nil(t, BuildDRWAAssetRecordKey(nil))
	require.Nil(t, BuildDRWAAssetRecordKey([]byte{}))

	// Non-empty returns non-nil
	require.NotNil(t, BuildDRWATokenPolicyKey([]byte("T")))
	require.NotNil(t, BuildDRWAHolderMirrorKey([]byte("T"), []byte("A")))
	require.NotNil(t, BuildDRWAHolderProfileKey([]byte("A")))
	require.NotNil(t, BuildDRWAHolderAuditorAuthorizationKey([]byte("T"), []byte("A")))
	require.NotNil(t, BuildDRWAAssetRecordKey([]byte("T")))
}

// ---------------------------------------------------------------------------
// G-01: Coverage for GetAssetRecord paths
// ---------------------------------------------------------------------------

func TestGetAssetRecord_EmptyTokenIdentifier(t *testing.T) {
	t.Parallel()

	reader, err := newDRWAAccountsReader(&mock.AccountsStub{
		LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
			return mock.NewUserAccount(address), nil
		},
	})
	require.NoError(t, err)

	_, err = reader.GetAssetRecord(nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "empty token identifier")
}

func TestGetAssetRecord_RetrieveError(t *testing.T) {
	t.Parallel()

	systemAccount := mock.NewAccountWrapMock(core.SystemAccountAddress)
	systemAccount.RetrieveValueCalled = func(key []byte) ([]byte, uint32, error) {
		return nil, 0, errors.New("storage error")
	}

	reader, err := newDRWAAccountsReader(&mock.AccountsStub{
		LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
			return systemAccount, nil
		},
	})
	require.NoError(t, err)

	_, err = reader.GetAssetRecord([]byte("CARBON-1"))
	require.Error(t, err)
}

func TestGetTokenPolicy_NilTrieOnEmptySystemAccountMeansMissingPolicy(t *testing.T) {
	t.Parallel()

	systemAccount := mock.NewAccountWrapMock(core.SystemAccountAddress)
	systemAccount.RetrieveValueCalled = func(key []byte) ([]byte, uint32, error) {
		return nil, 0, errors.New("trie is nil")
	}

	reader, err := newDRWAAccountsReader(&mock.AccountsStub{
		LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
			return systemAccount, nil
		},
	})
	require.NoError(t, err)

	policy, err := reader.GetTokenPolicy([]byte("SHOW-c9ac27"))
	require.NoError(t, err)
	require.Nil(t, policy)
}

func TestGetTokenPolicy_NilTrieWithRootHashFailsClosed(t *testing.T) {
	t.Parallel()

	systemAccount := mock.NewAccountWrapMock(core.SystemAccountAddress)
	systemAccount.SetRootHash([]byte("non-empty-root"))
	systemAccount.RetrieveValueCalled = func(key []byte) ([]byte, uint32, error) {
		return nil, 0, errors.New("trie is nil")
	}

	reader, err := newDRWAAccountsReader(&mock.AccountsStub{
		LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
			return systemAccount, nil
		},
	})
	require.NoError(t, err)

	_, err = reader.GetTokenPolicy([]byte("CARBON-1"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "trie is nil")
}

func TestGetAssetRecord_EmptyData(t *testing.T) {
	t.Parallel()

	systemAccount := mock.NewAccountWrapMock(core.SystemAccountAddress)

	reader, err := newDRWAAccountsReader(&mock.AccountsStub{
		LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
			return systemAccount, nil
		},
	})
	require.NoError(t, err)

	record, err := reader.GetAssetRecord([]byte("CARBON-1"))
	require.NoError(t, err)
	require.Nil(t, record)
}

func TestGetAssetRecord_ValidData(t *testing.T) {
	t.Parallel()

	systemAccount := mock.NewAccountWrapMock(core.SystemAccountAddress)
	body, _ := json.Marshal(&drwaAssetRecordView{WindDownInitiated: true, WindDownRound: 42})
	wrapped, _ := json.Marshal(&drwaStoredValue{Version: 1, Body: body})
	require.NoError(t, systemAccount.SaveKeyValue(BuildDRWAAssetRecordKey([]byte("CARBON-1")), wrapped))

	reader, err := newDRWAAccountsReader(&mock.AccountsStub{
		LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
			return systemAccount, nil
		},
	})
	require.NoError(t, err)

	record, err := reader.GetAssetRecord([]byte("CARBON-1"))
	require.NoError(t, err)
	require.NotNil(t, record)
	require.True(t, record.WindDownInitiated)
	require.Equal(t, uint64(42), record.WindDownRound)
}

func TestGetAssetRecord_CorruptData(t *testing.T) {
	t.Parallel()

	systemAccount := mock.NewAccountWrapMock(core.SystemAccountAddress)
	wrapped, _ := json.Marshal(&drwaStoredValue{Version: 1, Body: []byte("{corrupt")})
	require.NoError(t, systemAccount.SaveKeyValue(BuildDRWAAssetRecordKey([]byte("CARBON-1")), wrapped))

	reader, err := newDRWAAccountsReader(&mock.AccountsStub{
		LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
			return systemAccount, nil
		},
	})
	require.NoError(t, err)

	_, err = reader.GetAssetRecord([]byte("CARBON-1"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "drwa asset record unmarshal")
}

func TestIsDRWAActive_EmptyTokenIdentifier(t *testing.T) {
	t.Parallel()

	reader, err := newDRWAAccountsReader(&mock.AccountsStub{
		LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
			return mock.NewUserAccount(address), nil
		},
	})
	require.NoError(t, err)

	active, err := reader.IsDRWAActive(nil)
	require.False(t, active)
	require.Error(t, err)
	require.Contains(t, err.Error(), "empty token identifier")
}

func TestIsDRWAActive_ValidMarker(t *testing.T) {
	t.Parallel()

	systemAccount := mock.NewAccountWrapMock(core.SystemAccountAddress)
	require.NoError(t, systemAccount.SaveKeyValue(BuildDRWAActiveKey([]byte("CARBON-1")), []byte{1}))

	reader, err := newDRWAAccountsReader(&mock.AccountsStub{
		LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
			return systemAccount, nil
		},
	})
	require.NoError(t, err)

	active, err := reader.IsDRWAActive([]byte("CARBON-1"))
	require.NoError(t, err)
	require.True(t, active)
}

// ---------------------------------------------------------------------------
// G-01: Coverage for isDRWARegulatedToken — asset record exists but policy missing
// ---------------------------------------------------------------------------

func TestIsDRWARegulatedToken_AssetRecordExistsButNoPolicyDenies(t *testing.T) {
	t.Parallel()

	reader := &drwaReaderStub{
		getTokenPolicy: func(tokenIdentifier []byte) (*drwaTokenPolicyView, error) {
			return nil, nil // no policy
		},
		getAssetRecord: func(tokenIdentifier []byte) (*drwaAssetRecordView, error) {
			return &drwaAssetRecordView{WindDownInitiated: false}, nil // asset record exists
		},
	}

	regulated, _, err := isDRWARegulatedToken(reader, []byte("CARBON-1"), true)
	require.False(t, regulated)
	require.ErrorIs(t, err, errDRWAPolicyNotSynced)
}

func TestIsDRWARegulatedToken_AssetRecordReadError(t *testing.T) {
	t.Parallel()

	reader := &drwaReaderStub{
		getTokenPolicy: func(tokenIdentifier []byte) (*drwaTokenPolicyView, error) {
			return nil, nil
		},
		getAssetRecord: func(tokenIdentifier []byte) (*drwaAssetRecordView, error) {
			return nil, errors.New("asset read failed")
		},
	}

	_, _, err := isDRWARegulatedToken(reader, []byte("CARBON-1"), true)
	require.Error(t, err)
	require.Contains(t, err.Error(), "cannot read asset record")
}

func TestIsDRWARegulatedToken_DisabledPolicyWithAssetRecord(t *testing.T) {
	t.Parallel()

	reader := &drwaReaderStub{
		getTokenPolicy: func(tokenIdentifier []byte) (*drwaTokenPolicyView, error) {
			return &drwaTokenPolicyView{DRWAEnabled: false}, nil
		},
		getAssetRecord: func(tokenIdentifier []byte) (*drwaAssetRecordView, error) {
			return &drwaAssetRecordView{}, nil // exists
		},
	}

	regulated, _, err := isDRWARegulatedToken(reader, []byte("CARBON-1"), true)
	require.False(t, regulated)
	require.ErrorIs(t, err, errDRWAPolicyNotSynced)
}

func TestIsDRWARegulatedToken_ActiveWithoutPolicyFailsClosed(t *testing.T) {
	t.Parallel()

	reader := &drwaReaderStub{
		getTokenPolicy: func(tokenIdentifier []byte) (*drwaTokenPolicyView, error) {
			return nil, nil
		},
		isDRWAActive: func(tokenIdentifier []byte) (bool, error) {
			return true, nil
		},
	}

	regulated, _, err := isDRWARegulatedToken(reader, []byte("CARBON-1"), true)
	require.True(t, regulated)
	require.ErrorIs(t, err, errDRWAPolicyNotSynced)
}

// ---------------------------------------------------------------------------
// G-01: Coverage for validateDRWAMetadataUpdate GlobalPause path
// ---------------------------------------------------------------------------

func TestValidateDRWAMetadataUpdate_GlobalPauseDenies(t *testing.T) {
	t.Parallel()

	d := validateDRWAMetadataUpdate(&drwaTokenPolicyView{
		DRWAEnabled: true,
		GlobalPause: true,
	}, true)
	require.Equal(t, errDRWATokenPaused, d.DenialCode)
}

// ---------------------------------------------------------------------------
// G-01: Coverage for validateDRWAReceiver ReceiveLocked path
// ---------------------------------------------------------------------------

func TestValidateDRWAReceiver_ReceiveLockedDenies(t *testing.T) {
	t.Parallel()

	d := validateDRWAReceiver(&drwaTokenPolicyView{DRWAEnabled: true}, &drwaHolderMirrorView{
		KYCStatus:     "approved",
		AMLStatus:     "approved",
		ReceiveLocked: true,
	}, 100)
	require.Equal(t, errDRWAReceiveLocked, d.DenialCode)
}

// ---------------------------------------------------------------------------
// G-01: Coverage for validateDRWAReceiver auditor required path
// ---------------------------------------------------------------------------

func TestValidateDRWAReceiver_AuditorRequiredDenies(t *testing.T) {
	t.Parallel()

	d := validateDRWAReceiver(&drwaTokenPolicyView{
		DRWAEnabled:       true,
		StrictAuditorMode: true,
	}, &drwaHolderMirrorView{
		KYCStatus:         "approved",
		AMLStatus:         "approved",
		AuditorAuthorized: false,
	}, 100)
	require.Equal(t, errDRWAAuditorRequired, d.DenialCode)
}

// ---------------------------------------------------------------------------
// G-01: Coverage for decodeDRWAStoredJSON oversized payload rejection
// ---------------------------------------------------------------------------

func TestDecodeDRWAStoredJSON_RejectsOversized(t *testing.T) {
	t.Parallel()

	oversized := make([]byte, 65537) // > drwaMaxStoredJSONSize=65536
	oversized[0] = '{'
	err := decodeDRWAStoredJSON(oversized, &drwaTokenPolicyView{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "exceeds size limit")
}

// ---------------------------------------------------------------------------
// G-01: Coverage for decodeDRWAStoredJSON missing body path
// ---------------------------------------------------------------------------

func TestDecodeDRWAStoredJSON_MissingBody(t *testing.T) {
	t.Parallel()

	wrapped, _ := json.Marshal(&drwaStoredValue{Version: 1, Body: nil})
	err := decodeDRWAStoredJSON(wrapped, &drwaTokenPolicyView{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "missing drwa wrapped body")
}

// ---------------------------------------------------------------------------
// G-01: Coverage for classifyDRWADecodeFailureMetric default case
// ---------------------------------------------------------------------------

func TestClassifyDRWADecodeFailureMetric_DefaultCase(t *testing.T) {
	t.Parallel()

	// Unknown destination type → default metric
	result := classifyDRWADecodeFailureMetric([]byte{0x01}, &struct{}{}, errors.New("decode failure"))
	require.Equal(t, drwaGateMetricDecodeFailure, result)
}

// ---------------------------------------------------------------------------
// G-01: Coverage for decodeDRWABody with binary HolderAuditorAuthorization
// invalid boolean byte
// ---------------------------------------------------------------------------

func TestDecodeDRWABinaryAuditorAuth_InvalidBoolByte(t *testing.T) {
	t.Parallel()

	data := make([]byte, 9)
	data[8] = 2 // invalid — must be 0 or 1
	err := decodeDRWABinaryHolderAuditorAuthorization(data, &drwaHolderAuditorAuthorizationView{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid")
}

// ---------------------------------------------------------------------------
// G-01: Coverage for decodeDRWABinaryHolderMirror invalid boolean trailer
// ---------------------------------------------------------------------------

func TestDecodeDRWABinaryHolderMirror_InvalidBoolTrailer(t *testing.T) {
	t.Parallel()

	payload := make([]byte, 0, 64)
	payload = append(payload, make([]byte, 8)...)            // version
	payload = appendLenPrefixed(payload, []byte("approved")) // kyc
	payload = appendLenPrefixed(payload, []byte("approved")) // aml
	payload = appendLenPrefixed(payload, []byte("QIB"))      // investor class
	payload = appendLenPrefixed(payload, []byte("US"))       // jurisdiction

	expiry := make([]byte, 8)
	binary.BigEndian.PutUint64(expiry, 100)
	payload = append(payload, expiry...)
	payload = append(payload, 2, 0, 0) // TransferLocked=2 (invalid)

	err := decodeDRWABinaryHolderMirror(payload, &drwaHolderMirrorView{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "expected 0 or 1")
}

// ---------------------------------------------------------------------------
// G-01: Coverage for decodeDRWABinaryTokenPolicy reserved bytes non-zero
// ---------------------------------------------------------------------------

func TestDecodeDRWABinaryTokenPolicy_ReservedBytesNonZero(t *testing.T) {
	t.Parallel()

	data := make([]byte, 12)
	data[0] = 1 // DRWAEnabled
	data[5] = 1 // reserved byte non-zero
	err := decodeDRWABinaryTokenPolicy(data, &drwaTokenPolicyView{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "reserved bytes must be 0")
}

func TestDecodeDRWABinaryTokenPolicy_RejectsTrailingBytes(t *testing.T) {
	t.Parallel()

	data := make([]byte, drwaBinaryTokenPolicyMinSize+1)
	data[0] = 1 // DRWAEnabled
	data[drwaBinaryTokenPolicyMinSize] = 1

	err := decodeDRWABinaryTokenPolicy(data, &drwaTokenPolicyView{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid DRWA binary token policy payload length")
}

// ---------------------------------------------------------------------------
// G-01: GetTokenPolicy empty token identifier
// ---------------------------------------------------------------------------

func TestGetTokenPolicy_EmptyTokenIdentifier(t *testing.T) {
	t.Parallel()

	reader, err := newDRWAAccountsReader(&mock.AccountsStub{
		LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
			return mock.NewUserAccount(address), nil
		},
	})
	require.NoError(t, err)

	_, err = reader.GetTokenPolicy(nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "empty token identifier")
}

// ---------------------------------------------------------------------------
// G-01: GetHolderMirror empty inputs
// ---------------------------------------------------------------------------

func TestGetHolderMirror_EmptyInputs(t *testing.T) {
	t.Parallel()

	reader, err := newDRWAAccountsReader(&mock.AccountsStub{
		LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
			return mock.NewUserAccount(address), nil
		},
	})
	require.NoError(t, err)

	_, err = reader.GetHolderMirror(nil, []byte("addr"), nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "empty token identifier or address")

	_, err = reader.GetHolderMirror([]byte("token"), nil, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "empty token identifier or address")
}

func TestGetHolderMirror_NilTrieOnEmptyHolderAccountMeansMissingMirror(t *testing.T) {
	t.Parallel()

	holderAccount := mock.NewAccountWrapMock([]byte("holder"))
	holderAccount.RetrieveValueCalled = func(key []byte) ([]byte, uint32, error) {
		return nil, 0, errors.New("trie is nil")
	}

	reader, err := newDRWAAccountsReader(&mock.AccountsStub{
		LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
			return holderAccount, nil
		},
	})
	require.NoError(t, err)

	holder, err := reader.GetHolderMirror([]byte("CARBON-1"), holderAccount.AddressBytes(), holderAccount)
	require.NoError(t, err)
	require.Nil(t, holder)
}

// ---------------------------------------------------------------------------
// G-01: Coverage for profile-only merge (no holder mirror, only profile)
// ---------------------------------------------------------------------------

func TestGetHolderMirror_ProfileOnlyMerge(t *testing.T) {
	t.Parallel()

	holderAccount := mock.NewAccountWrapMock([]byte("holder"))
	accounts := &mock.AccountsStub{
		LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
			return holderAccount, nil
		},
	}

	reader, err := newDRWAAccountsReader(accounts)
	require.NoError(t, err)

	// No holder mirror, only profile
	mustSaveDRWAHolderProfile(t, holderAccount, "holder", &drwaHolderProfileView{
		KYCStatus:        "approved",
		AMLStatus:        "approved",
		InvestorClass:    "QIB",
		JurisdictionCode: "US",
		ExpiryRound:      99,
	})

	merged, err := reader.GetHolderMirror([]byte("CARBON-1"), []byte("holder"), nil)
	require.NoError(t, err)
	require.NotNil(t, merged)
	require.Equal(t, "approved", merged.KYCStatus)
	require.Equal(t, "QIB", merged.InvestorClass)
	require.Equal(t, "US", merged.JurisdictionCode)
	require.Zero(t, merged.ExpiryRound, "token-specific expiry requires a holder mirror")
	require.Equal(t, uint64(99), merged.IdentityExpiryRound)
}

func TestGetHolderMirror_AuditorAuthorizationOverridesHolderMirrorRegardlessOfVersion(t *testing.T) {
	t.Parallel()

	holderAccount := mock.NewAccountWrapMock([]byte("holder"))
	accounts := &mock.AccountsStub{
		LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
			return holderAccount, nil
		},
	}

	reader, err := newDRWAAccountsReader(accounts)
	require.NoError(t, err)

	mustSaveDRWAHolderBinary(
		t,
		holderAccount,
		"CARBON-1",
		"holder",
		5,
		"approved",
		"approved",
		"QIB",
		"US",
		99,
		false,
		false,
		false,
	)
	mustSaveDRWAHolderAuditorAuthorizationVersioned(t, holderAccount, "CARBON-1", "holder", true, 3)

	merged, err := reader.GetHolderMirror([]byte("CARBON-1"), []byte("holder"), nil)
	require.NoError(t, err)
	require.NotNil(t, merged)
	require.True(t, merged.AuditorAuthorized)
}

// ---------------------------------------------------------------------------
// G-01: GetHolderMirror nil result when no data exists
// ---------------------------------------------------------------------------

func TestGetHolderMirror_NilWhenNoData(t *testing.T) {
	t.Parallel()

	holderAccount := mock.NewAccountWrapMock([]byte("holder"))
	accounts := &mock.AccountsStub{
		LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
			return holderAccount, nil
		},
	}

	reader, err := newDRWAAccountsReader(accounts)
	require.NoError(t, err)

	merged, err := reader.GetHolderMirror([]byte("CARBON-1"), []byte("holder"), nil)
	require.NoError(t, err)
	require.Nil(t, merged)
}

// ---------------------------------------------------------------------------
// G-10: Fuzz target for binary token policy min-length boundary
// ---------------------------------------------------------------------------

func FuzzDecodeDRWABinaryTokenPolicy(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 11)) // one byte short
	f.Add(make([]byte, 12)) // exact minimum
	f.Add(make([]byte, 13)) // one byte over minimum
	// Valid policy with DRWAEnabled
	valid := make([]byte, 12)
	valid[0] = 1
	f.Add(valid)
	// Non-zero reserved bytes
	nonZeroReserved := make([]byte, 12)
	nonZeroReserved[0] = 1
	nonZeroReserved[6] = 0xFF
	f.Add(nonZeroReserved)

	f.Fuzz(func(t *testing.T, data []byte) {
		dest := &drwaTokenPolicyView{}
		err := decodeDRWABinaryTokenPolicy(data, dest)

		if len(data) < drwaBinaryTokenPolicyMinSize {
			if err == nil {
				t.Fatal("expected error for short payload")
			}
			return
		}
		if len(data) != drwaBinaryTokenPolicyMinSize {
			if err == nil {
				t.Fatal("expected error for non-canonical length")
			}
			return
		}
		// If reserved bytes are non-zero, must error
		for i := 4; i < drwaBinaryTokenPolicyMinSize && i < len(data); i++ {
			if data[i] != 0 {
				if err == nil {
					t.Fatal("expected error for non-zero reserved byte")
				}
				return
			}
		}
		// If we get here with no reserved-byte violations, decode should succeed
		if err != nil {
			t.Fatalf("unexpected error for valid-looking payload: %v", err)
		}
		// Validate boolean fields are correctly decoded
		if dest.DRWAEnabled != (data[0] == 1) {
			t.Fatalf("DRWAEnabled mismatch")
		}
		if dest.GlobalPause != (data[1] == 1) {
			t.Fatalf("GlobalPause mismatch")
		}
	})
}

// ---------------------------------------------------------------------------
// G-01: Coverage for decodeDRWABody — binary holder mirror path
// ---------------------------------------------------------------------------

func TestDecodeDRWABodyBinaryHolderMirror(t *testing.T) {
	t.Parallel()

	payload := make([]byte, 0, 64)
	payload = append(payload, make([]byte, 8)...)            // version
	payload = appendLenPrefixed(payload, []byte("approved")) // kyc
	payload = appendLenPrefixed(payload, []byte("clear"))    // aml
	payload = appendLenPrefixed(payload, []byte("QIB"))      // investor class
	payload = appendLenPrefixed(payload, []byte("US"))       // jurisdiction

	expiry := make([]byte, 8)
	binary.BigEndian.PutUint64(expiry, 200)
	payload = append(payload, expiry...)
	payload = append(payload, 0, 0, 1) // TransferLocked=false, ReceiveLocked=false, AuditorAuthorized=true

	holder := &drwaHolderMirrorView{}
	require.NoError(t, decodeDRWABody(payload, holder))
	require.Equal(t, "approved", holder.KYCStatus)
	require.Equal(t, "clear", holder.AMLStatus)
	require.Equal(t, "QIB", holder.InvestorClass)
	require.Equal(t, "US", holder.JurisdictionCode)
	require.Equal(t, uint64(200), holder.ExpiryRound)
	require.False(t, holder.TransferLocked)
	require.False(t, holder.ReceiveLocked)
	require.True(t, holder.AuditorAuthorized)
}

func TestDecodeDRWABodyBinaryHolderMirrorPolicyVersionEvaluated(t *testing.T) {
	t.Parallel()

	payload := make([]byte, 0, 72)
	payload = append(payload, make([]byte, 8)...)            // holder mirror version
	payload = appendLenPrefixed(payload, []byte("approved")) // kyc
	payload = appendLenPrefixed(payload, []byte("clear"))    // aml
	payload = appendLenPrefixed(payload, []byte("QIB"))      // investor class
	payload = appendLenPrefixed(payload, []byte("US"))       // jurisdiction

	expiry := make([]byte, 8)
	binary.BigEndian.PutUint64(expiry, 200)
	payload = append(payload, expiry...)
	payload = append(payload, 0, 0, 1) // TransferLocked=false, ReceiveLocked=false, AuditorAuthorized=true
	evaluatedVersion := make([]byte, 8)
	binary.BigEndian.PutUint64(evaluatedVersion, 4)
	payload = append(payload, evaluatedVersion...)

	holder := &drwaHolderMirrorView{}
	require.NoError(t, decodeDRWABody(payload, holder))
	require.Equal(t, uint64(4), holder.PolicyVersionEvaluated)
}

// ---------------------------------------------------------------------------
// G-01: Coverage for decodeDRWABinaryHolderProfile — full valid binary path
// ---------------------------------------------------------------------------

func TestDecodeDRWABinaryHolderProfileFullValid(t *testing.T) {
	t.Parallel()

	payload := make([]byte, 0, 64)
	payload = append(payload, make([]byte, 8)...)              // version
	payload = appendLenPrefixed(payload, []byte("approved"))   // kyc
	payload = appendLenPrefixed(payload, []byte("clear"))      // aml
	payload = appendLenPrefixed(payload, []byte("accredited")) // investor class
	payload = appendLenPrefixed(payload, []byte("GB"))         // jurisdiction

	expiry := make([]byte, 8)
	binary.BigEndian.PutUint64(expiry, 500)
	payload = append(payload, expiry...)

	profile := &drwaHolderProfileView{}
	require.NoError(t, decodeDRWABinaryHolderProfile(payload, profile))
	require.Equal(t, "approved", profile.KYCStatus)
	require.Equal(t, "clear", profile.AMLStatus)
	require.Equal(t, "accredited", profile.InvestorClass)
	require.Equal(t, "GB", profile.JurisdictionCode)
	require.Equal(t, uint64(500), profile.ExpiryRound)
}

// Also test profile through decodeDRWABody (the dispatch path)
func TestDecodeDRWABodyBinaryHolderProfile(t *testing.T) {
	t.Parallel()

	payload := make([]byte, 0, 64)
	payload = append(payload, make([]byte, 8)...)
	payload = appendLenPrefixed(payload, []byte("approved"))
	payload = appendLenPrefixed(payload, []byte("approved"))
	payload = appendLenPrefixed(payload, []byte("retail"))
	payload = appendLenPrefixed(payload, []byte("DE"))

	expiry := make([]byte, 8)
	binary.BigEndian.PutUint64(expiry, 300)
	payload = append(payload, expiry...)

	profile := &drwaHolderProfileView{}
	require.NoError(t, decodeDRWABody(payload, profile))
	require.Equal(t, "approved", profile.KYCStatus)
	require.Equal(t, "DE", profile.JurisdictionCode)
}

// ---------------------------------------------------------------------------
// G-01: decodeDRWABinaryHolderProfile — field read error in middle fields
// ---------------------------------------------------------------------------

func TestDecodeDRWABinaryHolderProfileFieldErrors(t *testing.T) {
	t.Parallel()

	// Valid version prefix but truncated after first field
	payload := make([]byte, 0, 32)
	payload = append(payload, make([]byte, 8)...)            // version
	payload = appendLenPrefixed(payload, []byte("approved")) // kyc
	// Missing aml field
	err := decodeDRWABinaryHolderProfile(payload, &drwaHolderProfileView{})
	require.Error(t, err)

	// Valid through aml but truncated investor class
	payload2 := make([]byte, 0, 32)
	payload2 = append(payload2, make([]byte, 8)...)
	payload2 = appendLenPrefixed(payload2, []byte("approved"))
	payload2 = appendLenPrefixed(payload2, []byte("clear"))
	// Missing investor class
	err = decodeDRWABinaryHolderProfile(payload2, &drwaHolderProfileView{})
	require.Error(t, err)

	// Valid through investor class but truncated jurisdiction
	payload3 := make([]byte, 0, 48)
	payload3 = append(payload3, make([]byte, 8)...)
	payload3 = appendLenPrefixed(payload3, []byte("approved"))
	payload3 = appendLenPrefixed(payload3, []byte("clear"))
	payload3 = appendLenPrefixed(payload3, []byte("QIB"))
	// Missing jurisdiction
	err = decodeDRWABinaryHolderProfile(payload3, &drwaHolderProfileView{})
	require.Error(t, err)
}

// Helpers are in drwa_integration_test.go (mustSaveDRWAHolderProfile,
// mustSaveDRWAHolderAuditorAuthorization, mustSaveDRWAHolder, etc.)
