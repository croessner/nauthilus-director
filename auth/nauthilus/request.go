package nauthilus

type Request struct {
	AuthLoginAttempt   uint   `json:"auth_login_attempt,omitempty"`
	Username           string `json:"username"`
	Password           string `json:"password,omitempty"`
	ClientIP           string `json:"client_ip,omitempty"`
	ClientPort         string `json:"client_port,omitempty"`
	ClientID           string `json:"client_id,omitempty"`
	LocalIP            string `json:"local_ip,omitempty"`
	LocalPort          string `json:"local_port,omitempty"`
	Service            string `json:"service"`
	Method             string `json:"method,omitempty"`
	SSL                string `json:"ssl,omitempty"`
	SSLSessionID       string `json:"ssl_session_id,omitempty"`
	SSLClientVerify    string `json:"ssl_client_verify,omitempty"`
	SSLClientDN        string `json:"ssl_client_dn,omitempty"`
	SSLClientCN        string `json:"ssl_client_cn,omitempty"`
	SSLIssuer          string `json:"ssl_issuer,omitempty"`
	SSLClientNotBefore string `json:"ssl_client_notbefore,omitempty"`
	SSLClientNotAfter  string `json:"ssl_client_notafter,omitempty"`
	SSLSubjectDN       string `json:"ssl_subject_dn,omitempty"`
	SSLIssuerDN        string `json:"ssl_issuer_dn,omitempty"`
	SSLClientSubjectDN string `json:"ssl_client_subject_dn,omitempty"`
	SSLClientIssuerDN  string `json:"ssl_client_issuer_dn,omitempty"`
	SSLProtocol        string `json:"ssl_protocol,omitempty"`
	SSLCipher          string `json:"ssl_cipher,omitempty"`
	SSLSerial          string `json:"ssl_serial,omitempty"`
	SSLFingerprint     string `json:"ssl_fingerprint,omitempty"`
}
