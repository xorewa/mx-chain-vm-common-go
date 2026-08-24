package vmcommon

import (
	"bytes"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/data/vm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetFirstReturnData_VMOutputWithNoReturnDataShouldErr(t *testing.T) {
	vmOutput := VMOutput{
		ReturnData: [][]byte{},
	}

	_, err := vmOutput.GetFirstReturnData(vm.AsBigInt)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "no return data")
}

func TestGetFirstReturnData_WithBadReturnDataKindShouldErr(t *testing.T) {
	vmOutput := VMOutput{
		ReturnData: [][]byte{[]byte("100")},
	}

	_, err := vmOutput.GetFirstReturnData(42)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "can't interpret")
}

func TestGetFirstReturnData(t *testing.T) {
	value := big.NewInt(100)

	vmOutput := VMOutput{
		ReturnData: [][]byte{value.Bytes()},
	}

	dataAsBigInt, _ := vmOutput.GetFirstReturnData(vm.AsBigInt)
	dataAsBigIntString, _ := vmOutput.GetFirstReturnData(vm.AsBigIntString)
	dataAsString, _ := vmOutput.GetFirstReturnData(vm.AsString)
	dataAsHex, _ := vmOutput.GetFirstReturnData(vm.AsHex)

	assert.Equal(t, value, dataAsBigInt)
	assert.Equal(t, "100", dataAsBigIntString)
	assert.Equal(t, string(value.Bytes()), dataAsString)
	assert.Equal(t, "64", dataAsHex)
}

func TestProtocolExecutionContractIsExplicitOptIn(t *testing.T) {
	ordinary := &VMOutput{}
	require.Nil(t, ordinary.ProtocolExecution)
	require.Equal(t, ProtocolExecutionOutcomeNone, ProtocolExecutionOutcome(0))

	ordinary.ProtocolExecution = &ProtocolExecutionInfo{
		MessageKind:        vm.ProtocolMessageKindDRWA,
		Outcome:            ProtocolExecutionOutcomeForward,
		LocalGasUsed:       1,
		ForwardedGas:       99,
		GasRefundRecipient: bytes.Repeat([]byte{0x11}, 32),
	}
	require.Equal(t, uint64(100), ordinary.ProtocolExecution.LocalGasUsed+ordinary.ProtocolExecution.ForwardedGas)
	require.Len(t, ordinary.ProtocolExecution.GasRefundRecipient, 32)
}

func TestProtocolExecutionContractIsExcludedFromJSON(t *testing.T) {
	t.Parallel()

	tests := map[string]*VMOutput{
		"nil contract": {},
		"populated contract": {
			ProtocolExecution: &ProtocolExecutionInfo{
				MessageKind:        vm.ProtocolMessageKindDRWA,
				Outcome:            ProtocolExecutionOutcomeForward,
				LocalGasUsed:       1122334455,
				ForwardedGas:       9988776655,
				GasRefundRecipient: bytes.Repeat([]byte{0x77}, 32),
			},
		},
	}

	for name, output := range tests {
		output := output
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			encoded, err := json.Marshal(output)
			require.NoError(t, err)
			require.NotContains(t, string(encoded), "ProtocolExecution")
			require.NotContains(t, string(encoded), "1122334455")
			require.NotContains(t, string(encoded), "9988776655")
			require.NotContains(t, string(encoded), "d3d3d3d3")

			decoded := make(map[string]json.RawMessage)
			require.NoError(t, json.Unmarshal(encoded, &decoded))
			require.NotContains(t, decoded, "ProtocolExecution")
		})
	}
}

func TestOutputContext_MergeCompleteAccounts(t *testing.T) {
	t.Parallel()

	transfer1 := OutputTransfer{
		Value:    big.NewInt(0),
		GasLimit: 9999,
		Data:     []byte("data1"),
	}
	left := &OutputAccount{
		Address:         []byte("addr1"),
		Nonce:           1,
		Balance:         big.NewInt(1000),
		BalanceDelta:    big.NewInt(10000),
		StorageUpdates:  nil,
		Code:            []byte("code1"),
		OutputTransfers: []OutputTransfer{transfer1},
	}
	right := &OutputAccount{
		Address:         []byte("addr2"),
		Nonce:           2,
		Balance:         big.NewInt(2000),
		BalanceDelta:    big.NewInt(20000),
		StorageUpdates:  map[string]*StorageUpdate{"key": {Data: []byte("data"), Offset: []byte("offset")}},
		Code:            []byte("code2"),
		OutputTransfers: []OutputTransfer{transfer1, transfer1},
	}

	expected := &OutputAccount{
		Address:         []byte("addr2"),
		Nonce:           2,
		Balance:         big.NewInt(2000),
		BalanceDelta:    big.NewInt(30000),
		StorageUpdates:  map[string]*StorageUpdate{"key": {Data: []byte("data"), Offset: []byte("offset")}},
		Code:            []byte("code2"),
		OutputTransfers: []OutputTransfer{transfer1, transfer1},
	}

	left.MergeOutputAccounts(right)
	require.Equal(t, expected, left)
}

func TestOutputTransfer_DefaultProtocolMessageKindIsNone(t *testing.T) {
	t.Parallel()

	transfer := OutputTransfer{}
	require.Equal(t, vm.ProtocolMessageKindNone, transfer.ProtocolMessageKind)
}
