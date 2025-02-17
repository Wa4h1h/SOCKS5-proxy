package credentials

import (
	"sync"
)

type CredentialsVerifier interface {
	Verify(username string, password string) error
}

type InMemoryCreds struct {
	sync.RWMutex
	Credentials map[string]string
}

func NewInMemoryCreds() *InMemoryCreds {
	return &InMemoryCreds{
		Credentials: make(map[string]string),
	}
}

func (i *InMemoryCreds) Verify(username string, password string) error {
	i.RLock()
	defer i.RUnlock()

	pass, ok := i.Credentials[username]
	if !ok {
		return ErrUserNotFound
	}

	if pass != password {
		return ErrCredentialsDontMatch
	}

	return nil
}

func (i *InMemoryCreds) Seed(creds map[string]string) {
	for key, value := range creds {
		i.Credentials[key] = value
	}
}
