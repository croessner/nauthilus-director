package commands

import (
	"strings"

	"github.com/croessner/nauthilus-director/interfaces"
)

func CalculateDisallowedMechanisms(allMechanisms, allowedMechanisms []string) []string {
	disallowed := make([]string, 0, len(allMechanisms))

	for _, mechanism := range allMechanisms {
		found := false

		for _, allowed := range allowedMechanisms {
			if strings.EqualFold(mechanism, allowed) {
				found = true

				break
			}
		}

		if !found {
			disallowed = append(disallowed, mechanism)
		}
	}

	return disallowed
}

func addTlsSessionInfos(session iface.IMAPSession, auth iface.Authenticator) {
	auth.SetTLSVerified(session.GetTLSVerified())
	auth.SetTLSProtocol(session.GetTLSProtocol())
	auth.SetTLSCipherSuite(session.GetTLSCipherSuite())
	auth.SetTLSClientCName(session.GetTLSClientCName())
	auth.SetTLSIssuerDN(session.GetTLSIssuerDN())
	auth.SetTLSClientDN(session.GetTLSClientDN())
	auth.SetTLSClientNotBefore(session.GetTLSClientNotBefore())
	auth.SetTLSClientNotAfter(session.GetTLSClientNotAfter())
	auth.SetTLSSerial(session.GetTLSSerial())
	auth.SetTLSClientIssuerDN(session.GetTLSClientIssuerDN())
	auth.SetTLSDNSNames(session.GetTLSDNSNames())
	auth.SetTLSFingerprint(session.GetTLSFingerprint())
}

func setupAuthenticator(session iface.IMAPSession, auth iface.Authenticator) {
	auth.SetTLSSecured(session.GetTLSFlag())
	auth.SetRemoteIP(session.GetRemoteIP())
	auth.SetRemotePort(session.GetRemotePort())
	auth.SetLocalIP(session.GetLocalIP())
	auth.SetLocalPort(session.GetLocalPort())
	auth.SetUserLookup(false)
	auth.SetHTTPOptions(session.GetNauthilus().HTTPClient)
	auth.SetTLSOptions(session.GetNauthilus().TLS)
	auth.SetNauthilusApi(session.GetNauthilus().Url)
	addTlsSessionInfos(session, auth)
}
