package grpc

import (
	"context"

	"github.com/golang/protobuf/proto"
	"google.golang.org/grpc"
)

// ExternalProcessorServer is the server API for ExternalProcessor service.
type ExternalProcessorServer interface {
	Process(ExternalProcessor_ProcessServer) error
}

type ExternalProcessor_ProcessServer interface {
	Send(*ProcessingResponse) error
	Recv() (*ProcessingRequest, error)
	grpc.ServerStream
}

type externalProcessorProcessServer struct {
	grpc.ServerStream
}

func (x *externalProcessorProcessServer) Send(m *ProcessingResponse) error {
	return x.ServerStream.SendMsg(m)
}

func (x *externalProcessorProcessServer) Recv() (*ProcessingRequest, error) {
	m := new(ProcessingRequest)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

// RegisterExternalProcessorServer registers the ExternalProcessorServer service with gRPC.
func RegisterExternalProcessorServer(s *grpc.Server, srv ExternalProcessorServer) {
	s.RegisterService(&ExternalProcessor_ServiceDesc, srv)
}

var ExternalProcessor_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "envoy.service.ext_proc.v3.ExternalProcessor",
	HandlerType: (*ExternalProcessorServer)(nil),
	Methods:     []grpc.MethodDesc{},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "Process",
			Handler:       _ExternalProcessor_Process_Handler,
			ServerStreams: true,
			ClientStreams: true,
		},
	},
	Metadata: "envoy/service/ext_proc/v3/external_processor.proto",
}

func _ExternalProcessor_Process_Handler(srv any, stream grpc.ServerStream) error {
	return srv.(ExternalProcessorServer).Process(&externalProcessorProcessServer{stream})
}

// ExternalProcessorClient is the client API for ExternalProcessor service.
type ExternalProcessorClient interface {
	Process(ctx context.Context, opts ...grpc.CallOption) (ExternalProcessor_ProcessClient, error)
}

type externalProcessorClient struct {
	cc grpc.ClientConnInterface
}

func NewExternalProcessorClient(cc grpc.ClientConnInterface) ExternalProcessorClient {
	return &externalProcessorClient{cc}
}

func (c *externalProcessorClient) Process(ctx context.Context, opts ...grpc.CallOption) (ExternalProcessor_ProcessClient, error) {
	stream, err := c.cc.NewStream(ctx, &ExternalProcessor_ServiceDesc.Streams[0], "/envoy.service.ext_proc.v3.ExternalProcessor/Process", opts...)
	if err != nil {
		return nil, err
	}
	x := &externalProcessorProcessClient{stream}
	return x, nil
}

type ExternalProcessor_ProcessClient interface {
	Send(*ProcessingRequest) error
	Recv() (*ProcessingResponse, error)
	grpc.ClientStream
}

type externalProcessorProcessClient struct {
	grpc.ClientStream
}

func (x *externalProcessorProcessClient) Send(m *ProcessingRequest) error {
	return x.ClientStream.SendMsg(m)
}

func (x *externalProcessorProcessClient) Recv() (*ProcessingResponse, error) {
	m := new(ProcessingResponse)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func init() {
	proto.RegisterType((*HttpStatus)(nil), "sidecar.HttpStatus")
	proto.RegisterType((*HeaderValue)(nil), "sidecar.HeaderValue")
	proto.RegisterType((*HeaderMap)(nil), "sidecar.HeaderMap")
	proto.RegisterType((*HttpHeaders)(nil), "sidecar.HttpHeaders")
	proto.RegisterType((*HttpBody)(nil), "sidecar.HttpBody")
	proto.RegisterType((*ImmediateResponse)(nil), "sidecar.ImmediateResponse")
	proto.RegisterType((*HeadersResponse)(nil), "sidecar.HeadersResponse")
	proto.RegisterType((*BodyResponse)(nil), "sidecar.BodyResponse")
	proto.RegisterType((*ProcessingRequest)(nil), "sidecar.ProcessingRequest")
	proto.RegisterType((*ProcessingResponse)(nil), "sidecar.ProcessingResponse")
}
