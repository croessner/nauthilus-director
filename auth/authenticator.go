package auth

type MockAuthenticator struct{}

func (a *MockAuthenticator) Authenticate(username, password string) bool {
	return username == "user" && password == "pass"
}
