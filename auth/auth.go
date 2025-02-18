package auth

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"slices"
	"time"

	"github.com/Wa4h1h/SOCKS5-proxy/credentials"
	"github.com/Wa4h1h/SOCKS5-proxy/utils"
)

func NewAuth(conn net.Conn, creds credentials.Credentials) *Auth {
	return &Auth{conn, creds}
}

func (a *Auth) Authenticate() error {
	b := make([]byte, 6)

	if err := a.Conn.SetDeadline(time.Now().
		Add(time.Duration(utils.Timeout) * time.Second)); err != nil {
		return fmt.Errorf("set conn deadline: %w", err)
	}

	n, err := a.Conn.Read(b)
	if err != nil {
		return fmt.Errorf("read auth request: %w", err)
	}

	if n < 3 {
		return ErrMalformedAuthRequest
	}

	authRequest := new(Request)

	if err := authRequest.parse(b[:n]); err != nil {
		return err
	}

	authResponse := Response{Ver: 0x05}

	switch {
	case slices.Contains(authRequest.Methods, 0x02):
		authResponse.Method = 0x02
	case slices.Contains(authRequest.Methods, 0x00):
		authResponse.Method = 0x00
	default:
		authResponse.Method = 0xff
	}

	w := new(bytes.Buffer)

	if err := binary.Write(w, binary.BigEndian, authResponse); err != nil {
		return fmt.Errorf("can not create auth response: %w", err)
	}

	if _, err := a.Conn.Write(w.Bytes()); err != nil {
		return fmt.Errorf("can not write auth response: %w", err)
	}

	if authResponse.Method == 0x02 {
		if err := a.authenticate(); err != nil {
			return err
		}
	}

	if err := a.Conn.SetDeadline(time.Time{}); err != nil {
		return fmt.Errorf("reset r/w deadline: %w", err)
	}

	return nil
}

func (a *Auth) authenticate() error {
	creds, err := a.parseCredentialRequest()
	if err != nil {
		return err
	}

	credsResponse := &CredentialResponse{
		Ver:    creds.Ver,
		Status: 0x00,
	}

	if err := a.CredsVerifier.Verify(creds.User, creds.Password); err != nil {
		log.Println(err)

		credsResponse.Status = 0x01
	}

	b := new(bytes.Buffer)

	if err := binary.Write(b, binary.BigEndian, credsResponse); err != nil {
		return fmt.Errorf("can not create credential response bytes: %w", err)
	}

	if _, err := a.Conn.Write(b.Bytes()); err != nil {
		return fmt.Errorf("can not write credential response: %w", err)
	}

	return nil
}

func (a *Auth) parseCredentialRequest() (*CredentialRequest, error) {
	creds := new(CredentialRequest)

	// parse header
	header := make([]byte, 2)

	_, err := a.Conn.Read(header)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil, ErrClientClosedConnection
		}

		return nil, fmt.Errorf("read credential request header: %w", err)
	}

	// version
	if err := binary.Read(bytes.NewReader(header[:1]),
		binary.BigEndian, &creds.Ver); err != nil {
		return nil, fmt.Errorf("parse version: %w", err)
	}

	// user length
	if err := binary.Read(bytes.NewReader(header[1:2]),
		binary.BigEndian, &creds.ULen); err != nil {
		return nil, fmt.Errorf("parse user length: %w", err)
	}

	// read username and password length
	user := make([]byte, creds.ULen+1)

	_, err = a.Conn.Read(user)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil, ErrClientClosedConnection
		}

		return nil, fmt.Errorf("read username and password length: %w", err)
	}

	creds.User = string(user[:creds.ULen])
	creds.PLen = user[len(user)-1]

	// read password
	password := make([]byte, creds.PLen)

	_, err = a.Conn.Read(password)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil, ErrClientClosedConnection
		}

		return nil, fmt.Errorf("read password: %w", err)
	}

	creds.Password = string(password)

	return creds, nil
}
