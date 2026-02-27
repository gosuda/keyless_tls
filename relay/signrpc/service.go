package signrpc

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	ServiceName = "keyless.v1.SignerService"

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

type SignerServiceServer interface {
	Sign(context.Context, *SignRequest) (*SignResponse, error)
}

type UnimplementedSignerServiceServer struct{}

func (UnimplementedSignerServiceServer) Sign(context.Context, *SignRequest) (*SignResponse, error) {
	return nil, status.Error(codes.Unimplemented, "method Sign not implemented")
}

func RegisterSignerServiceServer(registrar grpc.ServiceRegistrar, srv SignerServiceServer) {
	registrar.RegisterService(&grpc.ServiceDesc{
		ServiceName: ServiceName,
		HandlerType: (*SignerServiceServer)(nil),
		Methods: []grpc.MethodDesc{
			{
				MethodName: "Sign",
				Handler:    signHandler,
			},
		},
		Streams:  []grpc.StreamDesc{},
		Metadata: "keyless/v1/signer.proto",
	}, srv)
}

func signHandler(srv any, ctx context.Context, decoder func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	req := new(SignRequest)
	if err := decoder(req); err != nil {
		return nil, err
	}

	if interceptor == nil {
		return srv.(SignerServiceServer).Sign(ctx, req)
	}

	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/" + ServiceName + "/Sign"}
	handler := func(iCtx context.Context, iReq any) (any, error) {
		return srv.(SignerServiceServer).Sign(iCtx, iReq.(*SignRequest))
	}
	return interceptor(ctx, req, info, handler)
}

type SignerServiceClient interface {
	Sign(ctx context.Context, in *SignRequest, opts ...grpc.CallOption) (*SignResponse, error)
}

type signerServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewSignerServiceClient(cc grpc.ClientConnInterface) SignerServiceClient {
	return &signerServiceClient{cc: cc}
}

func (c *signerServiceClient) Sign(ctx context.Context, in *SignRequest, opts ...grpc.CallOption) (*SignResponse, error) {
	out := new(SignResponse)
	err := c.cc.Invoke(ctx, "/"+ServiceName+"/Sign", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}
