//go:build integration

package e2e

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"github.com/Panharoth06/raiwall/pkg/acl"
	"github.com/Panharoth06/raiwall/pkg/config"
	"github.com/Panharoth06/raiwall/pkg/engine"
	"github.com/Panharoth06/raiwall/pkg/sidecar"
	"github.com/Panharoth06/raiwall/pkg/telemetry"
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

	srv := sidecar.NewServer(sidecar.ExtProcConfig{
		MaxBodySize: 1024 * 1024,
		WAFEngine:   engine.NewSemanticEngine(),
		RingBuffer:  ringBuffer,
	})

	go func() {
		_ = srv.ServeListener(lis)
	}()
	defer srv.Stop()

	// Connect gRPC client via bufconn
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

	client := sidecar.NewExternalProcessorClient(conn)
	stream, err := client.Process(ctx)
	require.NoError(t, err)

	// 1. Send Request Headers
	reqHeaders := &sidecar.ProcessingRequest{
		Request: &sidecar.ProcessingRequest_RequestHeaders{
			RequestHeaders: &sidecar.HttpHeaders{
				Headers: &sidecar.HeaderMap{
					Headers: []*sidecar.HeaderValue{
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
	reqBodyThreat := &sidecar.ProcessingRequest{
		Request: &sidecar.ProcessingRequest_RequestBody{
			RequestBody: &sidecar.HttpBody{
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
	require.Equal(t, sidecar.StatusCode_Forbidden, imm.Status.Code)
	require.Contains(t, imm.Body, "Blocked by Raiwall Semantic WAF")

	// 3. New Stream: Benign Body Passthrough
	stream2, err := client.Process(ctx)
	require.NoError(t, err)

	err = stream2.Send(reqHeaders)
	require.NoError(t, err)
	_, err = stream2.Recv()
	require.NoError(t, err)

	reqBodyBenign := &sidecar.ProcessingRequest{
		Request: &sidecar.ProcessingRequest_RequestBody{
			RequestBody: &sidecar.HttpBody{
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

	srv := sidecar.NewServer(sidecar.ExtProcConfig{
		MaxBodySize: 1024 * 1024,
		WAFEngine:   engine.NewSemanticEngine(),
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

	snap := config.NewConfigSnapshot(1, config.ModeDefense, nil)
	snap.ACLRules = []*acl.ACLRule{rule}
	snap.Exceptions = []*acl.ExceptionRule{exc}
	config.StoreSnapshot(snap)
	defer config.StoreSnapshot(config.NewConfigSnapshot(0, config.ModeDefense, nil))

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

	client := sidecar.NewExternalProcessorClient(conn)

	// 1. Test ACL rule blocks request on header match
	stream, err := client.Process(ctx)
	require.NoError(t, err)

	reqHeadersBlocked := &sidecar.ProcessingRequest{
		Request: &sidecar.ProcessingRequest_RequestHeaders{
			RequestHeaders: &sidecar.HttpHeaders{
				Headers: &sidecar.HeaderMap{
					Headers: []*sidecar.HeaderValue{
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
	require.Equal(t, sidecar.StatusCode_Forbidden, imm.Status.Code)

	// 2. Test Exception bypasses semantic SQLi block on parameter "query"
	stream2, err := client.Process(ctx)
	require.NoError(t, err)

	reqHeadersAllow := &sidecar.ProcessingRequest{
		Request: &sidecar.ProcessingRequest_RequestHeaders{
			RequestHeaders: &sidecar.HttpHeaders{
				Headers: &sidecar.HeaderMap{
					Headers: []*sidecar.HeaderValue{
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

	reqBodyException := &sidecar.ProcessingRequest{
		Request: &sidecar.ProcessingRequest_RequestBody{
			RequestBody: &sidecar.HttpBody{
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
