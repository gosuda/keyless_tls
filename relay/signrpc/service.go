package signrpc

const (
	// SignPath is the single signer endpoint. Its wire contract is
	// transcript-bound: the request carries the TLS handshake transcript and
	// the response is its CertificateVerify signature.
	SignPath = "/v1/sign"
)

const (
	AlgorithmECDSASHA256       = "ECDSA_SHA256"
	AlgorithmECDSASHA384       = "ECDSA_SHA384"
	AlgorithmECDSASHA512       = "ECDSA_SHA512"
	AlgorithmRSAPKCS1v15SHA256 = "RSA_PKCS1V15_SHA256"
	AlgorithmRSAPKCS1v15SHA384 = "RSA_PKCS1V15_SHA384"
	AlgorithmRSAPKCS1v15SHA512 = "RSA_PKCS1V15_SHA512"
	AlgorithmRSAPSSSHA256      = "RSA_PSS_SHA256"
	AlgorithmRSAPSSSHA384      = "RSA_PSS_SHA384"
	AlgorithmRSAPSSSHA512      = "RSA_PSS_SHA512"
	AlgorithmEd25519           = "Ed25519"
)

type TranscriptSignRequest struct {
	KeyID               string `json:"key_id"`
	Algorithm           string `json:"algorithm"`
	Binding             []byte `json:"binding"`
	ClientHello         []byte `json:"client_hello"`
	ServerHello         []byte `json:"server_hello"`
	EncryptedExtensions []byte `json:"encrypted_extensions"`
	Certificate         []byte `json:"certificate"`
	TimestampUnix       int64  `json:"timestamp_unix"`
	Nonce               string `json:"nonce"`
}

type TranscriptSignResponse struct {
	KeyID     string `json:"key_id"`
	Algorithm string `json:"algorithm"`
	Signature []byte `json:"signature"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}
