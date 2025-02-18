package auth

import (
	"net"
	"testing"

	"github.com/Wa4h1h/SOCKS5-proxy/credentials"

	"github.com/stretchr/testify/assert"

	"github.com/stretchr/testify/require"
)

func TestAuth_Authenticate(t *testing.T) {
	c1, c2 := net.Pipe()

	defer func() {
		c1.Close()
		c2.Close()
	}()

	syncChan := make(chan struct{})

	testCases := []struct {
		name    string
		routine func(*testing.T)
	}{
		{
			name: "ValidCredentials",
			routine: func(t *testing.T) {
				c := credentials.NewInMemoryCreds()
				c.Seed(map[string]string{
					"test": "test",
				})

				a := NewAuth(c1, c)

				go func() {
					/*
						|ver=0x05|nmethods=0x02|methods=0x00 0x02|
					*/
					req := []byte{0x05, 0x02, 0x00, 0x02}

					_, err := c2.Write(req)

					require.NoError(t, err)
				}()

				go func() {
					require.NoError(t, a.Authenticate())
				}()

				b := make([]byte, 2)

				n, err := c2.Read(b)

				require.NoError(t, err)
				require.Equal(t, 2, n)

				assert.Equal(t, byte(0x05), b[0])
				assert.Equal(t, byte(0x02), b[1])

				go func() {
					/*
						|ver=0x05|ulen=0x04|user="test"|plen=0x04|password="test"|
					*/
					_, err := c2.Write([]byte{
						0x05, 0x04, 0x74, 0x65, 0x73, 0x74,
						0x04, 0x74, 0x65, 0x73, 0x74,
					})

					require.NoError(t, err)
				}()

				go func() {
					/*
						|ver=0x05|status=0x00|
					*/
					b = make([]byte, 2)

					n, err = c2.Read(b)

					require.NoError(t, err)
					require.Equal(t, 2, n)

					assert.Equal(t, byte(0x05), b[0])
					assert.Equal(t, byte(0x00), b[1])

					syncChan <- struct{}{}
				}()

				<-syncChan
			},
		},
		{
			name: "InvalidCredentials",
			routine: func(t *testing.T) {
				c := credentials.NewInMemoryCreds()
				c.Seed(map[string]string{
					"test": "wrong",
				})

				a := NewAuth(c1, c)

				go func() {
					/*
						|ver=0x05|nmethods=0x02|methods=0x00 0x02|
					*/
					req := []byte{0x05, 0x02, 0x00, 0x02}

					_, err := c2.Write(req)

					require.NoError(t, err)
				}()

				go func() {
					require.NoError(t, a.Authenticate())
				}()

				b := make([]byte, 2)

				n, err := c2.Read(b)

				require.NoError(t, err)
				require.Equal(t, 2, n)

				assert.Equal(t, byte(0x05), b[0])
				assert.Equal(t, byte(0x02), b[1])

				go func() {
					/*
						|ver=0x05|ulen=0x04|user="test"|plen=0x04|password="test"|
					*/
					_, err := c2.Write([]byte{
						0x05, 0x04, 0x74, 0x65, 0x73, 0x74,
						0x04, 0x74, 0x65, 0x73, 0x74,
					})

					require.NoError(t, err)
				}()

				go func() {
					/*
						|ver=0x05|status=0x01|
					*/
					b = make([]byte, 2)

					n, err = c2.Read(b)

					require.NoError(t, err)
					require.Equal(t, 2, n)

					assert.Equal(t, byte(0x05), b[0])
					assert.Equal(t, byte(0x01), b[1])

					syncChan <- struct{}{}
				}()

				<-syncChan
			},
		},
		{
			name: "UnsupportedAuth",
			routine: func(t *testing.T) {
				c := credentials.NewInMemoryCreds()
				a := NewAuth(c1, c)

				go func() {
					/*
						|ver=0x05|nmethods=0x02|methods=0x03 0x04|
					*/
					req := []byte{0x05, 0x02, 0x03, 0x04}

					_, err := c2.Write(req)

					require.NoError(t, err)
				}()

				go func() {
					require.NoError(t, a.Authenticate())
				}()

				b := make([]byte, 2)

				n, err := c2.Read(b)

				require.NoError(t, err)
				require.Equal(t, 2, n)

				assert.Equal(t, byte(0x05), b[0])
				assert.Equal(t, byte(0xff), b[1])
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			testCase.routine(t)
		})
	}
}
