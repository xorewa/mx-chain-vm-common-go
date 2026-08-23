package vmcommon

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// NON_NORMATIVE_DRWA_PROTOTYPE
// DO_NOT_EXPOSE_AS_PUBLIC_WIRE_FORMAT
// REPLACED_BY_PART_B

func TestNativeCallOriginPrototypeValuesAndDefault(t *testing.T) {
	t.Parallel()

	input := VMInput{}
	require.Equal(t, NativeCallOriginUnknown, input.NativeCallOrigin)
	require.Equal(t, NativeCallOrigin(0), NativeCallOriginUnknown)
	require.Equal(t, NativeCallOrigin(1), NativeCallOriginOriginalUserTransaction)
	require.Equal(t, NativeCallOrigin(2), NativeCallOriginDRWAProtocolMessage)
}
