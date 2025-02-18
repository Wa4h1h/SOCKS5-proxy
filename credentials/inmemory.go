package credentials

import (
	"encoding/csv"
	"fmt"
	"os"
	"sync"
)

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

func (i *InMemoryCreds) SeedFromCSV(file string) error {
	fd, err := os.Open(file)
	if err != nil {
		return fmt.Errorf("open csv %s: %w", file, err)
	}

	defer fd.Close()

	r := csv.NewReader(fd)

	records, err := r.ReadAll()
	if err != nil {
		return fmt.Errorf("read all records: %w", err)
	}

	for _, line := range records[1:] {
		i.Credentials[line[0]] = line[1]
	}

	return nil
}
