package credentials

import "errors"

var (
	ErrUserNotFound         = errors.New("user not found")
	ErrCredentialsDontMatch = errors.New("credentials dont match")
)
