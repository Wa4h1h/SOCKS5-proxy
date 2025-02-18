package credentials

type Credentials interface {
	Verify(username string, password string) error
}
