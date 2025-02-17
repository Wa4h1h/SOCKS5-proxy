package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRequest_parse(t *testing.T) {
	req := new(Request)

	require.NoError(t, req.parse([]byte{0x05, 0x2, 0x00, 0x02}))

	assert.Equal(t, byte(0x05), req.Ver)
	assert.Equal(t, byte(0x02), req.NMethods)
	assert.Equal(t, []byte{0x00, 0x02}, req.Methods)
}
