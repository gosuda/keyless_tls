package signrpc

const (
	// SignPath is the single signer endpoint. Its wire contract is
	// transcript-bound: the request carries the TLS handshake transcript and
	// the response is its CertificateVerify signature.
	SignPath = "/v1/sign"
)

const (
	AlgorithmECDSASHA256  = "ECDSA_SHA256"
	AlgorithmRSAPSSSHA256 = "RSA_PSS_SHA256"
	AlgorithmEd25519      = "Ed25519"
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
