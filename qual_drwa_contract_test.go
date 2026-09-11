package vmcommon

import (
	"encoding/json"
	"testing"

	"github.com/multiversx/mx-chain-core-go/data/vm"
	"github.com/stretchr/testify/require"
)

// NON_NORMATIVE_DRWA_PROTOTYPE
// DO_NOT_EXPOSE_AS_PUBLIC_WIRE_FORMAT
// REPLACED_BY_PART_B

func TestQualProtocolExecutionCannotBeInjectedThroughJSON(t *testing.T) {
	t.Parallel()

	payload := []byte(`{"ProtocolExecution":{"MessageKind":1,"Outcome":1,"LocalGasUsed":7,"ForwardedGas":11,"GasRefundRecipient":"AQI="}}`)
	output := &VMOutput{}

	require.NoError(t, json.Unmarshal(payload, output))
	require.Nil(t, output.ProtocolExecution)
}

func TestQualDRWAContractZeroValuesFailClosed(t *testing.T) {
	t.Parallel()

	input := VMInput{}
	output := VMOutput{}
	transfer := OutputTransfer{}

	require.Equal(t, NativeCallOriginUnknown, input.NativeCallOrigin)
	require.Nil(t, output.ProtocolExecution)
	require.Equal(t, vm.ProtocolMessageKindNone, transfer.ProtocolMessageKind)
	require.Equal(t, ProtocolExecutionOutcomeNone, ProtocolExecutionOutcome(0))
}
