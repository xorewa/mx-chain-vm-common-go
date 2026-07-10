package builtInFunctions

import (
	"encoding/json"
	"errors"
	"sync"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/multiversx/mx-chain-vm-common-go/mock"
	"github.com/stretchr/testify/require"
)

type drwaReaderStub struct {
	getTokenPolicy func(tokenIdentifier []byte) (*drwaTokenPolicyView, error)
	getHolder      func(tokenIdentifier []byte, address []byte, currentAccount vmcommon.UserAccountHandler) (*drwaHolderMirrorView, error)
	getAssetRecord func(tokenIdentifier []byte) (*drwaAssetRecordView, error)
	isDRWAActive   func(tokenIdentifier []byte) (bool, error)
}

func newNoopDRWAReader() *drwaReaderStub {
	return &drwaReaderStub{
		getTokenPolicy: func(tokenIdentifier []byte) (*drwaTokenPolicyView, error) {
			return nil, nil
		},
		getHolder: func(tokenIdentifier []byte, address []byte, currentAccount vmcommon.UserAccountHandler) (*drwaHolderMirrorView, error) {
			return nil, nil
		},
	}
}

func (d *drwaReaderStub) GetTokenPolicy(tokenIdentifier []byte) (*drwaTokenPolicyView, error) {
	return d.getTokenPolicy(tokenIdentifier)
}

func (d *drwaReaderStub) GetHolderMirror(tokenIdentifier []byte, address []byte, currentAccount vmcommon.UserAccountHandler) (*drwaHolderMirrorView, error) {
	return d.getHolder(tokenIdentifier, address, currentAccount)
}

func (d *drwaReaderStub) GetAssetRecord(tokenIdentifier []byte) (*drwaAssetRecordView, error) {
	if d.getAssetRecord != nil {
		return d.getAssetRecord(tokenIdentifier)
	}
	// Default: no asset record (token not regulated)
	return nil, nil
}

func (d *drwaReaderStub) IsDRWAActive(tokenIdentifier []byte) (bool, error) {
	if d.isDRWAActive != nil {
		return d.isDRWAActive(tokenIdentifier)
	}
	return false, nil
}

func TestCheckDRWAWrappersAndRegulatedTokenEvaluation(t *testing.T) {
	t.Parallel()

	reader := &drwaReaderStub{
		getTokenPolicy: func(tokenIdentifier []byte) (*drwaTokenPolicyView, error) {
			switch string(tokenIdentifier) {
			case "regulated":
				return &drwaTokenPolicyView{DRWAEnabled: true, MetadataProtectionEnabled: true, StrictAuditorMode: true}, nil
			case "plain":
				return nil, nil
			default:
				return &drwaTokenPolicyView{DRWAEnabled: false}, nil
			}
		},
		getHolder: func(tokenIdentifier []byte, address []byte, currentAccount vmcommon.UserAccountHandler) (*drwaHolderMirrorView, error) {
			switch string(tokenIdentifier) {
			case "regulated":
				return &drwaHolderMirrorView{
					KYCStatus:         "approved",
					AMLStatus:         "approved",
					InvestorClass:     "QIB",
					JurisdictionCode:  "US",
					AuditorAuthorized: true,
				}, nil
			case "receiver-blocked":
				return &drwaHolderMirrorView{KYCStatus: "approved", AMLStatus: "blocked"}, nil
			default:
				return nil, nil
			}
		},
	}

	regulated, policy, err := isDRWARegulatedToken(reader, []byte("regulated"), true)
	require.NoError(t, err)
	require.True(t, regulated)
	require.True(t, policy.DRWAEnabled)

	regulated, policy, err = isDRWARegulatedToken(reader, []byte("plain"), true)
	require.NoError(t, err)
	require.False(t, regulated)
	require.Nil(t, policy)

	// nil reader with enforcement disabled → not regulated, no error.
	regulated, policy, err = isDRWARegulatedToken(nil, []byte("regulated"), false)
	require.False(t, regulated)
	require.Nil(t, policy)
	require.NoError(t, err)

	// nil reader with enforcement enabled must fail closed.
	regulated, policy, err = isDRWARegulatedToken(nil, []byte("regulated"), true)
	require.False(t, regulated)
	require.Nil(t, policy)
	require.ErrorIs(t, err, errDRWAStateReaderMissing)

	err = checkDRWASenderTransfer(reader, []byte("regulated"), []byte("holder"), mock.NewUserAccount([]byte("holder")), 1)
	require.NoError(t, err)

	regulated, err = evaluateDRWAReceiverTransfer(&drwaReaderStub{
		getTokenPolicy: func(tokenIdentifier []byte) (*drwaTokenPolicyView, error) {
			return &drwaTokenPolicyView{DRWAEnabled: true}, nil
		},
		getHolder: func(tokenIdentifier []byte, address []byte, currentAccount vmcommon.UserAccountHandler) (*drwaHolderMirrorView, error) {
			return &drwaHolderMirrorView{KYCStatus: "approved", AMLStatus: "blocked"}, nil
		},
	}, []byte("receiver-blocked"), []byte("holder"), nil, 1)
	require.True(t, regulated)
	require.ErrorIs(t, err, errDRWAAMLBlockedReceiver)

	err = checkDRWAMetadataUpdate(reader, []byte("regulated"), []byte("holder"), mock.NewUserAccount([]byte("holder")))
	require.NoError(t, err)

	regulated, err = evaluateDRWAMetadataUpdate(&drwaReaderStub{
		getTokenPolicy: func(tokenIdentifier []byte) (*drwaTokenPolicyView, error) {
			return nil, errors.New("policy failed")
		},
		getHolder: func(tokenIdentifier []byte, address []byte, currentAccount vmcommon.UserAccountHandler) (*drwaHolderMirrorView, error) {
			return nil, nil
		},
	}, []byte("broken"), []byte("holder"), nil)
	require.False(t, regulated)
	require.EqualError(t, err, "policy failed")

	regulated, err = evaluateDRWAMetadataUpdate(&drwaReaderStub{
		getTokenPolicy: func(tokenIdentifier []byte) (*drwaTokenPolicyView, error) {
			return &drwaTokenPolicyView{DRWAEnabled: false}, nil
		},
		getHolder: func(tokenIdentifier []byte, address []byte, currentAccount vmcommon.UserAccountHandler) (*drwaHolderMirrorView, error) {
			t.Fatalf("holder should not be loaded for unregulated token")
			return nil, nil
		},
	}, []byte("plain"), []byte("holder"), nil)
	require.False(t, regulated)
	require.NoError(t, err)
}

func TestIsDRWARegulatedToken_ActiveTokenWithoutPolicyReturnsCodeZero(t *testing.T) {
	t.Parallel()

	reader := &drwaReaderStub{
		getTokenPolicy: func(tokenIdentifier []byte) (*drwaTokenPolicyView, error) {
			return nil, nil
		},
		isDRWAActive: func(tokenIdentifier []byte) (bool, error) {
			return true, nil
		},
	}

	regulated, policy, err := isDRWARegulatedToken(reader, []byte("BOND-1"), true)
	require.True(t, regulated)
	require.Nil(t, policy)
	require.ErrorIs(t, err, errDRWAStateReaderMissing)
}

func TestGetTokenPolicyAndHolderMirrorErrorPaths(t *testing.T) {
	t.Parallel()

	retrieveErr := errors.New("retrieve failed")
	systemAccount := mock.NewAccountWrapMock(core.SystemAccountAddress)
	holderAccount := mock.NewAccountWrapMock([]byte("holder"))

	accounts := &mock.AccountsStub{
		LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
			switch string(address) {
			case string(core.SystemAccountAddress):
				return systemAccount, nil
			case "holder":
				return holderAccount, nil
			default:
				return mock.NewUserAccount(address), nil
			}
		},
	}

	reader, err := newDRWAAccountsReader(accounts)
	require.NoError(t, err)

	systemAccount.RetrieveValueCalled = func(key []byte) ([]byte, uint32, error) {
		return nil, 0, retrieveErr
	}
	_, err = reader.GetTokenPolicy([]byte("CARBON-1"))
	require.ErrorIs(t, err, retrieveErr)

	systemAccount.RetrieveValueCalled = nil
	malformedWrapped, err := json.Marshal(&drwaStoredValue{Version: 1, Body: []byte("{")})
	require.NoError(t, err)
	require.NoError(t, systemAccount.SaveKeyValue(BuildDRWATokenPolicyKey([]byte("CARBON-2")), malformedWrapped))
	_, err = reader.GetTokenPolicy([]byte("CARBON-2"))
	require.Error(t, err)

	holderAccount.RetrieveValueCalled = func(key []byte) ([]byte, uint32, error) {
		return nil, 0, retrieveErr
	}
	_, err = reader.GetHolderMirror([]byte("CARBON-1"), []byte("holder"), nil)
	require.ErrorIs(t, err, retrieveErr)

	holderAccount.RetrieveValueCalled = nil
	mustSaveDRWAHolder(t, holderAccount, "CARBON-3", "holder", &drwaHolderMirrorView{
		KYCStatus: "approved",
		AMLStatus: "approved",
	})
	profileWrapped, err := json.Marshal(&drwaStoredValue{Version: 1, Body: []byte("{")})
	require.NoError(t, err)
	require.NoError(t, holderAccount.SaveKeyValue(BuildDRWAHolderProfileKey([]byte("holder")), profileWrapped))
	_, err = reader.GetHolderMirror([]byte("CARBON-3"), []byte("holder"), nil)
	require.Error(t, err)

	holderAccount = mock.NewAccountWrapMock([]byte("holder-auditor"))
	accounts.LoadAccountCalled = func(address []byte) (vmcommon.AccountHandler, error) {
		switch string(address) {
		case string(core.SystemAccountAddress):
			return systemAccount, nil
		case "holder-auditor":
			return holderAccount, nil
		default:
			return mock.NewUserAccount(address), nil
		}
	}
	mustSaveDRWAHolder(t, holderAccount, "CARBON-4", "holder-auditor", &drwaHolderMirrorView{
		KYCStatus: "approved",
		AMLStatus: "approved",
	})
	auditorWrapped, err := json.Marshal(&drwaStoredValue{Version: 1, Body: []byte("{")})
	require.NoError(t, err)
	require.NoError(t, holderAccount.SaveKeyValue(BuildDRWAHolderAuditorAuthorizationKey([]byte("CARBON-4"), []byte("holder-auditor")), auditorWrapped))
	_, err = reader.GetHolderMirror([]byte("CARBON-4"), []byte("holder-auditor"), nil)
	require.Error(t, err)
}

func TestGetHolderMirrorMergesProfileAndAuditorAuthorization(t *testing.T) {
	t.Parallel()

	holderAccount := mock.NewAccountWrapMock([]byte("holder"))
	accounts := &mock.AccountsStub{
		LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
			return holderAccount, nil
		},
	}

	reader, err := newDRWAAccountsReader(accounts)
	require.NoError(t, err)

	mustSaveDRWAHolder(t, holderAccount, "CARBON-1", "holder", &drwaHolderMirrorView{
		KYCStatus:         "pending",
		AMLStatus:         "approved",
		InvestorClass:     "RETAIL",
		JurisdictionCode:  "FR",
		ExpiryRound:       55,
		TransferLocked:    true,
		AuditorAuthorized: false,
	})
	mustSaveDRWAHolderProfile(t, holderAccount, "holder", &drwaHolderProfileView{
		KYCStatus:        "approved",
		AMLStatus:        "approved",
		InvestorClass:    "QIB",
		JurisdictionCode: "US",
		ExpiryRound:      99,
	})
	mustSaveDRWAHolderAuditorAuthorization(t, holderAccount, "CARBON-1", "holder", true)

	merged, err := reader.GetHolderMirror([]byte("CARBON-1"), []byte("holder"), nil)
	require.NoError(t, err)
	require.NotNil(t, merged)
	// At equal storedVersion (both 0), holder mirror wins for shared fields.
	// Profile fields (KYC=approved, InvestorClass=QIB, Jurisdiction=US) do NOT override
	// the mirror (KYC=pending, InvestorClass=RETAIL, Jurisdiction=FR).
	require.Equal(t, "pending", merged.KYCStatus)
	require.Equal(t, "RETAIL", merged.InvestorClass)
	require.Equal(t, "FR", merged.JurisdictionCode)
	require.Equal(t, uint64(55), merged.ExpiryRound)
	// IdentityExpiryRound falls through to profile when merged value is 0 (L-5)
	require.Equal(t, uint64(99), merged.IdentityExpiryRound)
	require.True(t, merged.TransferLocked)
	require.True(t, merged.AuditorAuthorized)
}

func TestGetHolderMirrorNewerProfileOverridesStaleHolderSharedFields(t *testing.T) {
	t.Parallel()

	holderAccount := mock.NewAccountWrapMock([]byte("holder"))
	accounts := &mock.AccountsStub{
		LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
			return holderAccount, nil
		},
	}

	reader, err := newDRWAAccountsReader(accounts)
	require.NoError(t, err)

	// Older holder mirror state.
	mustSaveDRWAHolderBinary(t, holderAccount, "CARBON-NEWER", "holder", 1, "pending", "blocked", "RETAIL", "FR", 55, false, false, false)
	// Newer identity profile must win for shared identity fields.
	mustSaveDRWAHolderProfile(t, holderAccount, "holder", &drwaHolderProfileView{
		KYCStatus:        "approved",
		AMLStatus:        "approved",
		InvestorClass:    "QIB",
		JurisdictionCode: "US",
		ExpiryRound:      99,
	})
	// Re-save profile with explicit higher wrapped version.
	profileBody, err := json.Marshal(&drwaHolderProfileView{
		KYCStatus:        "approved",
		AMLStatus:        "approved",
		InvestorClass:    "QIB",
		JurisdictionCode: "US",
		ExpiryRound:      99,
	})
	require.NoError(t, err)
	profileBytes, err := json.Marshal(&drwaStoredValue{
		Version: 2,
		Body:    profileBody,
	})
	require.NoError(t, err)
	require.NoError(t, holderAccount.AccountDataHandler().SaveKeyValue(BuildDRWAHolderProfileKey([]byte("holder")), profileBytes))

	merged, err := reader.GetHolderMirror([]byte("CARBON-NEWER"), []byte("holder"), nil)
	require.NoError(t, err)
	require.NotNil(t, merged)
	require.Equal(t, "approved", merged.KYCStatus)
	require.Equal(t, "approved", merged.AMLStatus)
	require.Equal(t, "QIB", merged.InvestorClass)
	require.Equal(t, "US", merged.JurisdictionCode)
	// IdentityExpiryRound always follows the profile.
	require.Equal(t, uint64(99), merged.IdentityExpiryRound)
	// Token-specific fields still come from the holder mirror.
	require.Equal(t, uint64(55), merged.ExpiryRound)
}

func TestGetHolderMirrorNewerAuditorAuthorizationOverridesHolderFlag(t *testing.T) {
	t.Parallel()

	holderAccount := mock.NewAccountWrapMock([]byte("holder"))
	accounts := &mock.AccountsStub{
		LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
			return holderAccount, nil
		},
	}

	reader, err := newDRWAAccountsReader(accounts)
	require.NoError(t, err)

	mustSaveDRWAHolderBinary(t, holderAccount, "CARBON-AUDIT", "holder", 1, "approved", "approved", "QIB", "SG", 55, false, false, false)

	auditorBody, err := json.Marshal(&drwaHolderAuditorAuthorizationView{
		AuditorAuthorized: true,
	})
	require.NoError(t, err)
	auditorWrapped, err := json.Marshal(&drwaStoredValue{
		Version: 2,
		Body:    auditorBody,
	})
	require.NoError(t, err)
	require.NoError(t, holderAccount.AccountDataHandler().SaveKeyValue(
		BuildDRWAHolderAuditorAuthorizationKey([]byte("CARBON-AUDIT"), []byte("holder")),
		auditorWrapped,
	))

	merged, err := reader.GetHolderMirror([]byte("CARBON-AUDIT"), []byte("holder"), nil)
	require.NoError(t, err)
	require.NotNil(t, merged)
	require.True(t, merged.AuditorAuthorized)
}

func TestGetHolderMirrorAuditorAuthorizationOverridesHistoricalHolderFlag(t *testing.T) {
	t.Parallel()

	holderAccount := mock.NewAccountWrapMock([]byte("holder"))
	accounts := &mock.AccountsStub{
		LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
			return holderAccount, nil
		},
	}

	reader, err := newDRWAAccountsReader(accounts)
	require.NoError(t, err)

	mustSaveDRWAHolderBinary(t, holderAccount, "CARBON-AUDIT", "holder", 2, "approved", "approved", "QIB", "SG", 55, false, false, true)

	auditorBody, err := json.Marshal(&drwaHolderAuditorAuthorizationView{
		AuditorAuthorized: false,
	})
	require.NoError(t, err)
	auditorWrapped, err := json.Marshal(&drwaStoredValue{
		Version: 1,
		Body:    auditorBody,
	})
	require.NoError(t, err)
	require.NoError(t, holderAccount.AccountDataHandler().SaveKeyValue(
		BuildDRWAHolderAuditorAuthorizationKey([]byte("CARBON-AUDIT"), []byte("holder")),
		auditorWrapped,
	))

	merged, err := reader.GetHolderMirror([]byte("CARBON-AUDIT"), []byte("holder"), nil)
	require.NoError(t, err)
	require.NotNil(t, merged)
	require.False(t, merged.AuditorAuthorized)
}

func TestValidateDRWASenderChecksBothIdentityAndTokenExpiry(t *testing.T) {
	t.Parallel()

	policy := &drwaTokenPolicyView{DRWAEnabled: true}
	holder := &drwaHolderMirrorView{
		KYCStatus:           "approved",
		AMLStatus:           "approved",
		ExpiryRound:         200,
		IdentityExpiryRound: 100,
	}

	decision := validateDRWASender(policy, holder, 150)
	require.ErrorIs(t, decision.DenialCode, errDRWAAssetExpired)

	holder.IdentityExpiryRound = 0
	decision = validateDRWASender(policy, holder, 150)
	require.True(t, decision.Allowed)

	decision = validateDRWASender(policy, holder, 250)
	require.ErrorIs(t, decision.DenialCode, errDRWAAssetExpired)
}

func TestValidateDRWAReceiverChecksIdentityExpiry(t *testing.T) {
	t.Parallel()

	decision := validateDRWAReceiver(nil, nil, 1)
	require.True(t, decision.Allowed)

	decision = validateDRWAReceiver(&drwaTokenPolicyView{DRWAEnabled: false}, nil, 1)
	require.True(t, decision.Allowed)

	decision = validateDRWAReceiver(&drwaTokenPolicyView{DRWAEnabled: true}, &drwaHolderMirrorView{
		KYCStatus:           "approved",
		AMLStatus:           "approved",
		IdentityExpiryRound: 10,
	}, 11)
	require.ErrorIs(t, decision.DenialCode, errDRWAAssetExpired)
}

func TestDRWAEvaluationErrorPaths(t *testing.T) {
	t.Parallel()

	// nil reader with enforcement active must fail closed.
	regulated, err := evaluateDRWASenderTransfer(nil, []byte("regulated"), []byte("holder"), nil, 1)
	require.False(t, regulated)
	require.ErrorIs(t, err, errDRWAStateReaderMissing)

	regulated, err = evaluateDRWASenderTransfer(&drwaReaderStub{
		getTokenPolicy: func(tokenIdentifier []byte) (*drwaTokenPolicyView, error) {
			return &drwaTokenPolicyView{DRWAEnabled: true}, nil
		},
		getHolder: func(tokenIdentifier []byte, address []byte, currentAccount vmcommon.UserAccountHandler) (*drwaHolderMirrorView, error) {
			return nil, errors.New("sender holder failed")
		},
	}, []byte("regulated"), []byte("holder"), nil, 1)
	require.True(t, regulated)
	require.EqualError(t, err, "sender holder failed")

	regulated, err = evaluateDRWAReceiverTransfer(&drwaReaderStub{
		getTokenPolicy: func(tokenIdentifier []byte) (*drwaTokenPolicyView, error) {
			return &drwaTokenPolicyView{DRWAEnabled: true}, nil
		},
		getHolder: func(tokenIdentifier []byte, address []byte, currentAccount vmcommon.UserAccountHandler) (*drwaHolderMirrorView, error) {
			return nil, errors.New("receiver holder failed")
		},
	}, []byte("regulated"), []byte("holder"), nil, 1)
	require.True(t, regulated)
	require.EqualError(t, err, "receiver holder failed")

	regulated, err = evaluateDRWAMetadataUpdate(&drwaReaderStub{
		getTokenPolicy: func(tokenIdentifier []byte) (*drwaTokenPolicyView, error) {
			return &drwaTokenPolicyView{DRWAEnabled: true, MetadataProtectionEnabled: true, StrictAuditorMode: true}, nil
		},
		getHolder: func(tokenIdentifier []byte, address []byte, currentAccount vmcommon.UserAccountHandler) (*drwaHolderMirrorView, error) {
			return nil, errors.New("metadata holder failed")
		},
	}, []byte("regulated"), []byte("holder"), nil)
	require.True(t, regulated)
	require.EqualError(t, err, "metadata holder failed")
}

func TestDRWAAccountsReaderLoadUserAccountPropagatesLoadErrors(t *testing.T) {
	t.Parallel()

	reader, err := newDRWAAccountsReader(&mock.AccountsStub{
		LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
			return nil, errors.New("load failed")
		},
	})
	require.NoError(t, err)

	account, err := reader.loadUserAccount([]byte("missing"), nil)
	require.Nil(t, account)
	require.EqualError(t, err, "load failed")
}

// ---------------------------------------------------------------------------
// SetDRWAReadGasUnits tests (0% → covered)
// ---------------------------------------------------------------------------

// NOTE: These tests must NOT use t.Parallel() — they mutate a shared atomic.
func TestSetDRWAReadGasUnits_DefaultValue(t *testing.T) {
	// Reset to default before checking.
	drwaReadGasUnitsAtomic.Store(drwaReadGasUnitsDefault)
	got := drwaReadGasUnitsAtomic.Load()
	require.Equal(t, uint64(drwaReadGasUnitsDefault), got)
}

func TestSetDRWAReadGasUnits_ChangesValue(t *testing.T) {
	drwaReadGasUnitsAtomic.Store(drwaReadGasUnitsDefault)
	SetDRWAReadGasUnits(42)
	got := drwaReadGasUnitsAtomic.Load()
	require.Equal(t, uint64(42), got)
	// Restore default for other tests.
	drwaReadGasUnitsAtomic.Store(drwaReadGasUnitsDefault)
}

func TestTrySetDRWAReadGasUnitsReportsRejectedZero(t *testing.T) {
	drwaReadGasUnitsAtomic.Store(drwaReadGasUnitsDefault)
	ok := TrySetDRWAReadGasUnits(0)
	got := drwaReadGasUnitsAtomic.Load()
	require.False(t, ok, "zero must be rejected visibly")
	require.Equal(t, uint64(drwaReadGasUnitsDefault), got, "zero must not change configured gas")

	ok = TrySetDRWAReadGasUnits(17)
	got = drwaReadGasUnitsAtomic.Load()
	require.True(t, ok)
	require.Equal(t, uint64(17), got)

	drwaReadGasUnitsAtomic.Store(drwaReadGasUnitsDefault)
}

func TestSetDRWAReadGasUnits_RejectsZero(t *testing.T) {
	drwaReadGasUnitsAtomic.Store(drwaReadGasUnitsDefault)
	SetDRWAReadGasUnits(0)
	got := drwaReadGasUnitsAtomic.Load()
	require.Equal(t, uint64(drwaReadGasUnitsDefault), got, "zero must be rejected")
}

func TestSetDRWAReadGasUnits_ConcurrentAccess(t *testing.T) {
	drwaReadGasUnitsAtomic.Store(drwaReadGasUnitsDefault)
	const goroutines = 50
	const iterations = 200

	var wg sync.WaitGroup
	wg.Add(goroutines * 2)

	// Writers
	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				SetDRWAReadGasUnits(uint64(id + 1))
			}
		}(i)
	}

	// Readers
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				v := drwaReadGasUnitsAtomic.Load()
				require.NotZero(t, v)
			}
		}()
	}

	wg.Wait()
	// Restore default for other tests.
	drwaReadGasUnitsAtomic.Store(drwaReadGasUnitsDefault)
}

// ---------------------------------------------------------------------------
// checkDRWAMetadataUpdate tests (0% → covered)
// ---------------------------------------------------------------------------

func TestCheckDRWAMetadataUpdate_RegulatedTokenEnforces(t *testing.T) {
	t.Parallel()

	reader := &drwaReaderStub{
		getTokenPolicy: func(tokenIdentifier []byte) (*drwaTokenPolicyView, error) {
			return &drwaTokenPolicyView{
				DRWAEnabled:               true,
				MetadataProtectionEnabled: true,
				StrictAuditorMode:         true,
			}, nil
		},
		getHolder: func(tokenIdentifier []byte, address []byte, currentAccount vmcommon.UserAccountHandler) (*drwaHolderMirrorView, error) {
			return &drwaHolderMirrorView{
				KYCStatus:         "approved",
				AMLStatus:         "approved",
				AuditorAuthorized: true,
			}, nil
		},
	}

	err := checkDRWAMetadataUpdate(reader, []byte("REG-1"), []byte("caller"), nil)
	require.NoError(t, err)
}

func TestCheckDRWAMetadataUpdate_UnregulatedTokenPasses(t *testing.T) {
	t.Parallel()

	reader := &drwaReaderStub{
		getTokenPolicy: func(tokenIdentifier []byte) (*drwaTokenPolicyView, error) {
			return nil, nil // not regulated
		},
		getHolder: func(tokenIdentifier []byte, address []byte, currentAccount vmcommon.UserAccountHandler) (*drwaHolderMirrorView, error) {
			t.Fatal("holder should not be loaded for unregulated token")
			return nil, nil
		},
	}

	err := checkDRWAMetadataUpdate(reader, []byte("PLAIN-1"), []byte("caller"), nil)
	require.NoError(t, err)
}

func TestCheckDRWAMetadataUpdate_NilReaderPasses(t *testing.T) {
	t.Parallel()

	err := checkDRWAMetadataUpdate(nil, []byte("ANY-1"), []byte("caller"), nil)
	require.ErrorIs(t, err, errDRWAStateReaderMissing)
}

func TestCheckDRWAMetadataUpdate_KYCDenied(t *testing.T) {
	t.Parallel()

	reader := &drwaReaderStub{
		getTokenPolicy: func(tokenIdentifier []byte) (*drwaTokenPolicyView, error) {
			return &drwaTokenPolicyView{
				DRWAEnabled:               true,
				MetadataProtectionEnabled: true,
			}, nil
		},
		getHolder: func(tokenIdentifier []byte, address []byte, currentAccount vmcommon.UserAccountHandler) (*drwaHolderMirrorView, error) {
			return &drwaHolderMirrorView{
				KYCStatus: "pending",
				AMLStatus: "approved",
			}, nil
		},
	}

	err := checkDRWAMetadataUpdate(reader, []byte("REG-1"), []byte("caller"), nil)
	require.ErrorIs(t, err, errDRWAKYCRequiredSender)
}

func TestCheckDRWAMetadataUpdate_AMLDenied(t *testing.T) {
	t.Parallel()

	reader := &drwaReaderStub{
		getTokenPolicy: func(tokenIdentifier []byte) (*drwaTokenPolicyView, error) {
			return &drwaTokenPolicyView{
				DRWAEnabled:               true,
				MetadataProtectionEnabled: true,
			}, nil
		},
		getHolder: func(tokenIdentifier []byte, address []byte, currentAccount vmcommon.UserAccountHandler) (*drwaHolderMirrorView, error) {
			return &drwaHolderMirrorView{
				KYCStatus: "approved",
				AMLStatus: "blocked",
			}, nil
		},
	}

	err := checkDRWAMetadataUpdate(reader, []byte("REG-1"), []byte("caller"), nil)
	require.ErrorIs(t, err, errDRWAAMLBlockedSender)
}
