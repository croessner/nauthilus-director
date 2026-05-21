package commands

import "github.com/croessner/nauthilus-director/interfaces"

func addTlsSessionInfos(session iface.LMTPSession, auth iface.Authenticator) {
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
