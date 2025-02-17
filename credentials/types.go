package credentials

var CredsSources = map[CredentialSource]CredentialsVerifier{
	InMemory: NewInMemoryCreds(),
}
