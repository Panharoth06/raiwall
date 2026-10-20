//go:build integration

package e2e

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	grpcgo "google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"github.com/Panharoth06/raiwall/internal/adapters/inbound/grpc"
	"github.com/Panharoth06/raiwall/internal/core/acl"
	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/Panharoth06/raiwall/internal/core/telemetry"
	"github.com/Panharoth06/raiwall/internal/core/waf"
)

func TestSidecar_E2E_ThreatBlockAndPassthrough(t *testing.T) {
	lis := bufconn.Listen(1024 * 1024)
	defer lis.Close()

	ringBuffer := telemetry.NewRingBuffer(telemetry.RingBufferConfig{
		Capacity:      1000,
		FlushInterval: 500 * time.Millisecond,
		Handler:       func(events []*telemetry.ForensicEvent) error { return nil },
	})
	defer ringBuffer.Close()

	srv := grpc.NewServer(grpc.ExtProcConfig{
		MaxBodySize: 1024 * 1024,
		WAFEngine:   waf.NewSemanticEngine(),
		RingBuffer:  ringBuffer,
	})

	go func() {
		_ = srv.ServeListener(lis)
	}()
	defer srv.Stop()

	// Connect gRPC client via bufconn
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := grpcgo.DialContext(ctx, "bufnet",
		grpcgo.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return lis.Dial()
		}),
		grpcgo.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	defer conn.Close()

	client := grpc.NewExternalProcessorClient(conn)
	stream, err := client.Process(ctx)
	require.NoError(t, err)

	// 1. Send Request Headers
	reqHeaders := &grpc.ProcessingRequest{
		Request: &grpc.ProcessingRequest_RequestHeaders{
			RequestHeaders: &grpc.HttpHeaders{
				Headers: &grpc.HeaderMap{
					Headers: []*grpc.HeaderValue{
						{Key: ":method", Value: "POST"},
						{Key: ":path", Value: "/api/checkout"},
						{Key: "x-forwarded-for", Value: "198.51.100.42"},
					},
				},
				EndOfStream: false,
			},
		},
	}
	err = stream.Send(reqHeaders)
	require.NoError(t, err)

	resp, err := stream.Recv()
	require.NoError(t, err)
	require.NotNil(t, resp.GetRequestHeaders())

	// 2. Send Request Body containing SQL Injection
	reqBodyThreat := &grpc.ProcessingRequest{
		Request: &grpc.ProcessingRequest_RequestBody{
			RequestBody: &grpc.HttpBody{
				Body:        []byte("query=1 UNION SELECT username, password FROM users--"),
				EndOfStream: true,
			},
		},
	}
	err = stream.Send(reqBodyThreat)
	require.NoError(t, err)

	resp, err = stream.Recv()
	require.NoError(t, err)

	imm := resp.GetImmediateResponse()
	require.NotNil(t, imm, "expected threat to trigger 403 ImmediateResponse")
	require.Equal(t, grpc.StatusCode_Forbidden, imm.Status.Code)
	require.Contains(t, imm.Body, "Blocked by Raiwall Semantic WAF")

	// 3. New Stream: Benign Body Passthrough
	stream2, err := client.Process(ctx)
	require.NoError(t, err)

	err = stream2.Send(reqHeaders)
	require.NoError(t, err)
	_, err = stream2.Recv()
	require.NoError(t, err)

	reqBodyBenign := &grpc.ProcessingRequest{
		Request: &grpc.ProcessingRequest_RequestBody{
			RequestBody: &grpc.HttpBody{
				Body:        []byte("search=sneakers&category=footwear"),
				EndOfStream: true,
			},
		},
	}
	err = stream2.Send(reqBodyBenign)
	require.NoError(t, err)

	resp2, err := stream2.Recv()
	require.NoError(t, err)
	require.NotNil(t, resp2.GetRequestBody(), "expected benign body to receive continuation BodyResponse")
	require.Nil(t, resp2.GetImmediateResponse())
}

func TestSidecar_E2E_ACLRulesAndExceptions(t *testing.T) {
	lis := bufconn.Listen(1024 * 1024)
	defer lis.Close()

	srv := grpc.NewServer(grpc.ExtProcConfig{
		MaxBodySize: 1024 * 1024,
		WAFEngine:   waf.NewSemanticEngine(),
	})

	go func() {
		_ = srv.ServeListener(lis)
	}()
	defer srv.Stop()

	// Set active snapshot with an ACL rule and an exception rule
	rule := &acl.ACLRule{
		Name:       "block-bad-header",
		Expression: `headers["x-blocked"] == "true"`,
		Action:     acl.ActionBlock,
		StatusCode: 403,
	}
	require.NoError(t, rule.Compile(nil))

	exc := &acl.ExceptionRule{
		ID:        "exc-query-sqli",
		Host:      "*",
		Location:  "body",
		ParamName: "query",
		RuleID:    "SEMANTIC_SQLI",
	}

	snap := control.NewConfigSnapshot(1, control.ModeDefense, nil)
	snap.ACLRules = []*acl.ACLRule{rule}
	snap.Exceptions = []*acl.ExceptionRule{exc}
	control.StoreSnapshot(snap)
	defer control.StoreSnapshot(control.NewConfigSnapshot(0, control.ModeDefense, nil))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := grpcgo.DialContext(ctx, "bufnet",
		grpcgo.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return lis.Dial()
		}),
		grpcgo.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	defer conn.Close()

	client := grpc.NewExternalProcessorClient(conn)

	// 1. Test ACL rule blocks request on header match
	stream, err := client.Process(ctx)
	require.NoError(t, err)

	reqHeadersBlocked := &grpc.ProcessingRequest{
		Request: &grpc.ProcessingRequest_RequestHeaders{
			RequestHeaders: &grpc.HttpHeaders{
				Headers: &grpc.HeaderMap{
					Headers: []*grpc.HeaderValue{
						{Key: ":method", Value: "GET"},
						{Key: ":path", Value: "/data"},
						{Key: "x-blocked", Value: "true"},
					},
				},
				EndOfStream: true,
			},
		},
	}
	err = stream.Send(reqHeadersBlocked)
	require.NoError(t, err)

	resp, err := stream.Recv()
	require.NoError(t, err)
	imm := resp.GetImmediateResponse()
	require.NotNil(t, imm, "expected ACL rule to trigger 403 ImmediateResponse")
	require.Equal(t, grpc.StatusCode_Forbidden, imm.Status.Code)

	// 2. Test Exception bypasses semantic SQLi block on parameter "query"
	stream2, err := client.Process(ctx)
	require.NoError(t, err)

	reqHeadersAllow := &grpc.ProcessingRequest{
		Request: &grpc.ProcessingRequest_RequestHeaders{
			RequestHeaders: &grpc.HttpHeaders{
				Headers: &grpc.HeaderMap{
					Headers: []*grpc.HeaderValue{
						{Key: ":method", Value: "POST"},
						{Key: ":path", Value: "/search"},
					},
				},
				EndOfStream: false,
			},
		},
	}
	err = stream2.Send(reqHeadersAllow)
	require.NoError(t, err)
	_, err = stream2.Recv()
	require.NoError(t, err)

	reqBodyException := &grpc.ProcessingRequest{
		Request: &grpc.ProcessingRequest_RequestBody{
			RequestBody: &grpc.HttpBody{
				Body:        []byte("query=1 UNION SELECT username, password FROM users--"),
				EndOfStream: true,
			},
		},
	}
	err = stream2.Send(reqBodyException)
	require.NoError(t, err)

	resp2, err := stream2.Recv()
	require.NoError(t, err)
	require.NotNil(t, resp2.GetRequestBody(), "expected exception rule to bypass semantic WAF block")
	require.Nil(t, resp2.GetImmediateResponse())
}
