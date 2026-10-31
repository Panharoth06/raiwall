package grpc

import (
	"testing"

	"github.com/golang/protobuf/proto"
	"google.golang.org/protobuf/encoding/protowire"
)

// TestExtProcWireFieldNumbers pins the oneof field numbers to the Envoy v3
// ext_proc contract. Envoy decodes these numbers from the wire; a wrong tag
// silently routes request bodies to response handlers (or ignores blocks).
// Reference: envoy/service/ext_proc/v3/external_processor.proto.
func TestExtProcWireFieldNumbers(t *testing.T) {
	cases := []struct {
		name string
		msg  proto.Message
		want protowire.Number
	}{
		{"request_headers", &ProcessingRequest{Request: &ProcessingRequest_RequestHeaders{
			RequestHeaders: &HttpHeaders{Headers: &HeaderMap{}}}}, 2},
		{"response_headers", &ProcessingRequest{Request: &ProcessingRequest_ResponseHeaders{
			ResponseHeaders: &HttpHeaders{Headers: &HeaderMap{}}}}, 3},
		{"request_body", &ProcessingRequest{Request: &ProcessingRequest_RequestBody{
			RequestBody: &HttpBody{Body: []byte("x")}}}, 4},
		{"response_body", &ProcessingRequest{Request: &ProcessingRequest_ResponseBody{
			ResponseBody: &HttpBody{Body: []byte("x")}}}, 5},

		{"resp_request_headers", &ProcessingResponse{Response: &ProcessingResponse_RequestHeaders{
			RequestHeaders: &HeadersResponse{}}}, 1},
		{"resp_response_headers", &ProcessingResponse{Response: &ProcessingResponse_ResponseHeaders{
			ResponseHeaders: &HeadersResponse{}}}, 2},
		{"resp_request_body", &ProcessingResponse{Response: &ProcessingResponse_RequestBody{
			RequestBody: &BodyResponse{}}}, 3},
		{"resp_response_body", &ProcessingResponse{Response: &ProcessingResponse_ResponseBody{
			ResponseBody: &BodyResponse{}}}, 4},
		{"resp_immediate_response", &ProcessingResponse{Response: &ProcessingResponse_ImmediateResponse{
			ImmediateResponse: &ImmediateResponse{Body: "blocked"}}}, 7},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := proto.Marshal(tc.msg)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			num, _, n := protowire.ConsumeTag(raw)
			if n < 0 {
				t.Fatalf("consume tag: %v", protowire.ParseError(n))
			}
			if num != tc.want {
				t.Fatalf("field number = %d, want %d", num, tc.want)
			}
		})
	}
}
