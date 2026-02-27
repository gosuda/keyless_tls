package signrpc

const SignPath = "/v1/sign"

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
)

type SignRequest struct {
	KeyID         string `json:"key_id"`
	Algorithm     string `json:"algorithm"`
	Digest        []byte `json:"digest"`
	TimestampUnix int64  `json:"timestamp_unix"`
	Nonce         string `json:"nonce"`
}

type SignResponse struct {
	KeyID     string `json:"key_id"`
	Algorithm string `json:"algorithm"`
	Signature []byte `json:"signature"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}
