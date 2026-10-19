package sidecar

import (
	"context"
	"fmt"

	"github.com/golang/protobuf/proto"
	"google.golang.org/grpc"
)

// StatusCode corresponds to envoy.type.v3.StatusCode enum.
type StatusCode int32

const (
	StatusCode_Empty               StatusCode = 0
	StatusCode_Continue            StatusCode = 100
	StatusCode_OK                  StatusCode = 200
	StatusCode_Created             StatusCode = 201
	StatusCode_Forbidden           StatusCode = 403
	StatusCode_NotFound            StatusCode = 404
	StatusCode_TooManyRequests     StatusCode = 429
	StatusCode_InternalServerError StatusCode = 500
	StatusCode_ServiceUnavailable  StatusCode = 503
)

// HttpStatus corresponds to envoy.type.v3.HttpStatus.
type HttpStatus struct {
	Code             StatusCode `protobuf:"varint,1,opt,name=code,enum=sidecar.StatusCode" json:"code,omitempty"`
	XXX_unrecognized []byte     `json:"-"`
}

func (x *HttpStatus) Reset()         { *x = HttpStatus{} }
func (x *HttpStatus) String() string { return fmt.Sprintf("HttpStatus{%d}", x.Code) }
func (*HttpStatus) ProtoMessage()    {}

// HeaderValue corresponds to envoy.config.core.v3.HeaderValue.
type HeaderValue struct {
	Key              string `protobuf:"bytes,1,opt,name=key" json:"key,omitempty"`
	Value            string `protobuf:"bytes,2,opt,name=value" json:"value,omitempty"`
	RawValue         []byte `protobuf:"bytes,3,opt,name=raw_value,json=rawValue" json:"raw_value,omitempty"`
	XXX_unrecognized []byte `json:"-"`
}

func (x *HeaderValue) Reset()         { *x = HeaderValue{} }
func (x *HeaderValue) String() string { return fmt.Sprintf("HeaderValue{%s=%s}", x.Key, x.Value) }
func (*HeaderValue) ProtoMessage()    {}

// HeaderMap corresponds to envoy.config.core.v3.HeaderMap.
type HeaderMap struct {
	Headers          []*HeaderValue `protobuf:"bytes,1,rep,name=headers" json:"headers,omitempty"`
	XXX_unrecognized []byte         `json:"-"`
}

func (x *HeaderMap) Reset()         { *x = HeaderMap{} }
func (x *HeaderMap) String() string { return "HeaderMap{...}" }
func (*HeaderMap) ProtoMessage()    {}

// HttpHeaders corresponds to envoy.service.ext_proc.v3.HttpHeaders.
type HttpHeaders struct {
	Headers          *HeaderMap `protobuf:"bytes,1,opt,name=headers" json:"headers,omitempty"`
	EndOfStream      bool       `protobuf:"varint,3,opt,name=end_of_stream,json=endOfStream" json:"end_of_stream,omitempty"`
	XXX_unrecognized []byte     `json:"-"`
}

func (x *HttpHeaders) Reset()         { *x = HttpHeaders{} }
func (x *HttpHeaders) String() string { return "HttpHeaders{...}" }
func (*HttpHeaders) ProtoMessage()    {}

// HttpBody corresponds to envoy.service.ext_proc.v3.HttpBody.
type HttpBody struct {
	Body             []byte `protobuf:"bytes,1,opt,name=body" json:"body,omitempty"`
	EndOfStream      bool   `protobuf:"varint,2,opt,name=end_of_stream,json=endOfStream" json:"end_of_stream,omitempty"`
	XXX_unrecognized []byte `json:"-"`
}

func (x *HttpBody) Reset()         { *x = HttpBody{} }
func (x *HttpBody) String() string { return fmt.Sprintf("HttpBody{len=%d}", len(x.Body)) }
func (*HttpBody) ProtoMessage()    {}

// ProcessingRequest corresponds to envoy.service.ext_proc.v3.ProcessingRequest.
type ProcessingRequest struct {
	AsyncMode        bool                        `protobuf:"varint,1,opt,name=async_mode,json=asyncMode" json:"async_mode,omitempty"`
	Request          isProcessingRequest_Request `protobuf_oneof:"request"`
	XXX_unrecognized []byte                      `json:"-"`
}

func (x *ProcessingRequest) Reset()         { *x = ProcessingRequest{} }
func (x *ProcessingRequest) String() string { return "ProcessingRequest{...}" }
func (*ProcessingRequest) ProtoMessage()    {}

type isProcessingRequest_Request interface {
	isProcessingRequest_Request()
}

type ProcessingRequest_RequestHeaders struct {
	RequestHeaders *HttpHeaders `protobuf:"bytes,2,opt,name=request_headers,json=requestHeaders,oneof"`
}
type ProcessingRequest_RequestBody struct {
	RequestBody *HttpBody `protobuf:"bytes,3,opt,name=request_body,json=requestBody,oneof"`
}
type ProcessingRequest_ResponseHeaders struct {
	ResponseHeaders *HttpHeaders `protobuf:"bytes,4,opt,name=response_headers,json=responseHeaders,oneof"`
}
type ProcessingRequest_ResponseBody struct {
	ResponseBody *HttpBody `protobuf:"bytes,5,opt,name=response_body,json=responseBody,oneof"`
}

func (*ProcessingRequest_RequestHeaders) isProcessingRequest_Request()  {}
func (*ProcessingRequest_RequestBody) isProcessingRequest_Request()     {}
func (*ProcessingRequest_ResponseHeaders) isProcessingRequest_Request() {}
func (*ProcessingRequest_ResponseBody) isProcessingRequest_Request()    {}

// XXX_OneofWrappers is for the internal use of the proto package.
func (*ProcessingRequest) XXX_OneofWrappers() []interface{} {
	return []interface{}{
		(*ProcessingRequest_RequestHeaders)(nil),
		(*ProcessingRequest_RequestBody)(nil),
		(*ProcessingRequest_ResponseHeaders)(nil),
		(*ProcessingRequest_ResponseBody)(nil),
	}
}

func (m *ProcessingRequest) GetRequest() isProcessingRequest_Request {
	if m != nil {
		return m.Request
	}
	return nil
}

func (x *ProcessingRequest) GetRequestHeaders() *HttpHeaders {
	if x != nil {
		if r, ok := x.Request.(*ProcessingRequest_RequestHeaders); ok {
			return r.RequestHeaders
		}
	}
	return nil
}

func (x *ProcessingRequest) GetRequestBody() *HttpBody {
	if x != nil {
		if r, ok := x.Request.(*ProcessingRequest_RequestBody); ok {
			return r.RequestBody
		}
	}
	return nil
}

func (x *ProcessingRequest) GetResponseHeaders() *HttpHeaders {
	if x != nil {
		if r, ok := x.Request.(*ProcessingRequest_ResponseHeaders); ok {
			return r.ResponseHeaders
		}
	}
	return nil
}

func (x *ProcessingRequest) GetResponseBody() *HttpBody {
	if x != nil {
		if r, ok := x.Request.(*ProcessingRequest_ResponseBody); ok {
			return r.ResponseBody
		}
	}
	return nil
}

// ImmediateResponse corresponds to envoy.service.ext_proc.v3.ImmediateResponse.
type ImmediateResponse struct {
	Status           *HttpStatus `protobuf:"bytes,1,opt,name=status" json:"status,omitempty"`
	Body             string      `protobuf:"bytes,3,opt,name=body" json:"body,omitempty"`
	Details          string      `protobuf:"bytes,5,opt,name=details" json:"details,omitempty"`
	XXX_unrecognized []byte      `json:"-"`
}

func (x *ImmediateResponse) Reset()         { *x = ImmediateResponse{} }
func (x *ImmediateResponse) String() string { return fmt.Sprintf("ImmediateResponse{%s}", x.Details) }
func (*ImmediateResponse) ProtoMessage()    {}

// HeadersResponse corresponds to envoy.service.ext_proc.v3.HeadersResponse.
type HeadersResponse struct {
	XXX_unrecognized []byte `json:"-"`
}

func (x *HeadersResponse) Reset()         { *x = HeadersResponse{} }
func (x *HeadersResponse) String() string { return "HeadersResponse{}" }
func (*HeadersResponse) ProtoMessage()    {}

// BodyResponse corresponds to envoy.service.ext_proc.v3.BodyResponse.
type BodyResponse struct {
	XXX_unrecognized []byte `json:"-"`
}

func (x *BodyResponse) Reset()         { *x = BodyResponse{} }
func (x *BodyResponse) String() string { return "BodyResponse{}" }
func (*BodyResponse) ProtoMessage()    {}

// ProcessingResponse corresponds to envoy.service.ext_proc.v3.ProcessingResponse.
type ProcessingResponse struct {
	Response         isProcessingResponse_Response `protobuf_oneof:"response"`
	XXX_unrecognized []byte                        `json:"-"`
}

func (x *ProcessingResponse) Reset()         { *x = ProcessingResponse{} }
func (x *ProcessingResponse) String() string { return "ProcessingResponse{...}" }
func (*ProcessingResponse) ProtoMessage()    {}

type isProcessingResponse_Response interface {
	isProcessingResponse_Response()
}

type ProcessingResponse_RequestHeaders struct {
	RequestHeaders *HeadersResponse `protobuf:"bytes,1,opt,name=request_headers,json=requestHeaders,oneof"`
}
type ProcessingResponse_RequestBody struct {
	RequestBody *BodyResponse `protobuf:"bytes,2,opt,name=request_body,json=requestBody,oneof"`
}
type ProcessingResponse_ResponseHeaders struct {
	ResponseHeaders *HeadersResponse `protobuf:"bytes,3,opt,name=response_headers,json=responseHeaders,oneof"`
}
type ProcessingResponse_ResponseBody struct {
	ResponseBody *BodyResponse `protobuf:"bytes,4,opt,name=response_body,json=responseBody,oneof"`
}
type ProcessingResponse_ImmediateResponse struct {
	ImmediateResponse *ImmediateResponse `protobuf:"bytes,5,opt,name=immediate_response,json=immediateResponse,oneof"`
}

func (*ProcessingResponse_RequestHeaders) isProcessingResponse_Response()     {}
func (*ProcessingResponse_RequestBody) isProcessingResponse_Response()        {}
func (*ProcessingResponse_ResponseHeaders) isProcessingResponse_Response()    {}
func (*ProcessingResponse_ResponseBody) isProcessingResponse_Response()       {}
func (*ProcessingResponse_ImmediateResponse) isProcessingResponse_Response()  {}

// XXX_OneofWrappers is for the internal use of the proto package.
func (*ProcessingResponse) XXX_OneofWrappers() []interface{} {
	return []interface{}{
		(*ProcessingResponse_RequestHeaders)(nil),
		(*ProcessingResponse_RequestBody)(nil),
		(*ProcessingResponse_ResponseHeaders)(nil),
		(*ProcessingResponse_ResponseBody)(nil),
		(*ProcessingResponse_ImmediateResponse)(nil),
	}
}

func (m *ProcessingResponse) GetResponse() isProcessingResponse_Response {
	if m != nil {
		return m.Response
	}
	return nil
}

func (x *ProcessingResponse) GetRequestHeaders() *HeadersResponse {
	if x != nil {
		if r, ok := x.Response.(*ProcessingResponse_RequestHeaders); ok {
			return r.RequestHeaders
		}
	}
	return nil
}

func (x *ProcessingResponse) GetRequestBody() *BodyResponse {
	if x != nil {
		if r, ok := x.Response.(*ProcessingResponse_RequestBody); ok {
			return r.RequestBody
		}
	}
	return nil
}

func (x *ProcessingResponse) GetImmediateResponse() *ImmediateResponse {
	if x != nil {
		if r, ok := x.Response.(*ProcessingResponse_ImmediateResponse); ok {
			return r.ImmediateResponse
		}
	}
	return nil
}

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
