package auth

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"github.com/Wa4h1h/SOCKS5-proxy/credentials"
)

type Auth struct {
	Conn          net.Conn
	CredsVerifier credentials.Credentials
}

type Request struct {
	Ver      byte
	NMethods byte
	Methods  []byte
}

func (a *Request) parse(data []byte) error {
	err := errors.Join(binary.Read(bytes.NewReader(data[:1]), binary.BigEndian, &a.Ver),
		binary.Read(bytes.NewReader(data[1:2]), binary.BigEndian, &a.NMethods))
	if err != nil {
		return fmt.Errorf("parse auth request: %w", err)
	}

	if len(data) > 2 {
		a.Methods = data[2:]
	}

	return nil
}

type Response struct {
	Ver    byte
	Method byte
}

type CredentialRequest struct {
	Ver      byte
	ULen     byte
	User     string
	PLen     byte
	Password string
}

type CredentialResponse struct {
	Ver    byte
	Status byte
}
