package auth

import "errors"

var (
	ErrMalformedAuthRequest   = errors.New("malformed auth request")
	ErrClientClosedConnection = errors.New("client closed connection")
)
