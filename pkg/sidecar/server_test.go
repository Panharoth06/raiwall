package sidecar

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/Panharoth06/raiwall/pkg/config"
	"github.com/Panharoth06/raiwall/pkg/engine"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

func TestSidecar_ThreatBlockAndPassthrough(t *testing.T) {
	lis := bufconn.Listen(1024 * 1024)
	defer lis.Close()

	srv := NewServer(ExtProcConfig{
		MaxBodySize: 1024 * 1024,
	})
	go func() {
		_ = srv.ServeListener(lis)
	}()
	defer srv.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Connect in-memory gRPC client via bufconn
	conn, err := grpc.DialContext(ctx, "bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return lis.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	defer conn.Close()

	client := NewExternalProcessorClient(conn)

	// Test 1: Benign Request (Passthrough)
	stream, err := client.Process(ctx)
	require.NoError(t, err)

	// Send headers
	err = stream.Send(&ProcessingRequest{
		Request: &ProcessingRequest_RequestHeaders{
			RequestHeaders: &HttpHeaders{
				Headers: &HeaderMap{
					Headers: []*HeaderValue{
						{Key: ":method", Value: "POST"},
						{Key: ":path", Value: "/api/submit"},
						{Key: ":authority", Value: "api.example.com"},
						{Key: "x-real-ip", Value: "203.0.113.195"},
					},
				},
			},
		},
	})
	require.NoError(t, err)

	resp, err := stream.Recv()
	require.NoError(t, err)
	require.NotNil(t, resp.GetRequestHeaders())

	// Send benign body
	err = stream.Send(&ProcessingRequest{
		Request: &ProcessingRequest_RequestBody{
			RequestBody: &HttpBody{
				Body:        []byte("name=alice&message=hello+world"),
				EndOfStream: true,
			},
		},
	})
	require.NoError(t, err)

	resp, err = stream.Recv()
	require.NoError(t, err)
	require.NotNil(t, resp.GetRequestBody())

	// Test 2: Malicious SQLi Request (Blocked with 403 ImmediateResponse)
	stream2, err := client.Process(ctx)
	require.NoError(t, err)

	err = stream2.Send(&ProcessingRequest{
		Request: &ProcessingRequest_RequestHeaders{
			RequestHeaders: &HttpHeaders{
				Headers: &HeaderMap{
					Headers: []*HeaderValue{
						{Key: ":method", Value: "POST"},
						{Key: ":path", Value: "/api/login"},
						{Key: ":authority", Value: "api.example.com"},
					},
				},
			},
		},
	})
	require.NoError(t, err)

	resp, err = stream2.Recv()
	require.NoError(t, err)
	require.NotNil(t, resp.GetRequestHeaders())

	// Send malicious SQL injection payload
	err = stream2.Send(&ProcessingRequest{
		Request: &ProcessingRequest_RequestBody{
			RequestBody: &HttpBody{
				Body:        []byte("username=admin' OR 1=1--"),
				EndOfStream: true,
			},
		},
	})
	require.NoError(t, err)

	resp, err = stream2.Recv()
	require.NoError(t, err)
	imm := resp.GetImmediateResponse()
	require.NotNil(t, imm)
	require.Equal(t, StatusCode_Forbidden, imm.Status.Code)
	require.Contains(t, imm.Body, "Blocked by Raiwall Semantic WAF")
}

func TestSidecar_LargeBodyPassthrough(t *testing.T) {
	lis := bufconn.Listen(1024 * 1024)
	defer lis.Close()

	// Max body size 10 KB for test
	srv := NewServer(ExtProcConfig{
		MaxBodySize: 10 * 1024,
	})
	go func() {
		_ = srv.ServeListener(lis)
	}()
	defer srv.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(ctx, "bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return lis.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	defer conn.Close()

	client := NewExternalProcessorClient(conn)

	stream, err := client.Process(ctx)
	require.NoError(t, err)

	_ = stream.Send(&ProcessingRequest{
		Request: &ProcessingRequest_RequestHeaders{
			RequestHeaders: &HttpHeaders{
				Headers: &HeaderMap{
					Headers: []*HeaderValue{
						{Key: ":method", Value: "POST"},
						{Key: ":path", Value: "/upload"},
						{Key: ":authority", Value: "upload.example.com"},
					},
				},
			},
		},
	})
	_, err = stream.Recv()
	require.NoError(t, err)

	// Send 50 KB body (> 10 KB limit)
	largePayload := make([]byte, 50*1024)
	err = stream.Send(&ProcessingRequest{
		Request: &ProcessingRequest_RequestBody{
			RequestBody: &HttpBody{
				Body:        largePayload,
				EndOfStream: true,
			},
		},
	})
	require.NoError(t, err)

	// Stream should pass without OOM
	resp, err := stream.Recv()
	require.NoError(t, err)
	require.NotNil(t, resp.GetRequestBody())
}

func init() {
	config.StoreSnapshot(config.NewConfigSnapshot(1, config.ModeDefense, nil))
	_ = engine.NewSemanticEngine()
}
