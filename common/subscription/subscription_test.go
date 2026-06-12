package subscription

import (
	"encoding/base64"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestResolveSubscriptionAsSIP008_SS2022KeepsRawPSK(t *testing.T) {
	const password = "RCF/0OOYmo6crue3LwlEyD8izLAbuUuyPic/vasJH/o="
	payload := []byte(`{
		"version": 1,
		"servers": [
			{
				"id": "n1",
				"remarks": "test",
				"server": "127.0.0.1",
				"server_port": 443,
				"password": "` + password + `",
				"method": "2022-blake3-aes-256-gcm",
				"plugin": "",
				"plugin_opts": ""
			}
		]
	}`)

	nodes, err := ResolveSubscriptionAsSIP008(logrus.New(), payload)
	if err != nil {
		t.Fatalf("ResolveSubscriptionAsSIP008: %v", err)
	}
	if len(nodes) != 1 {
		t.Fatalf("expected one node, got %d", len(nodes))
	}

	u, err := url.Parse(nodes[0])
	if err != nil {
		t.Fatalf("parse generated node: %v", err)
	}

	if _, hasPassword := u.User.Password(); hasPassword {
		t.Fatalf("expected canonical base64 userinfo, got %q", u.User.String())
	}

	decoded, err := base64.RawURLEncoding.DecodeString(u.User.Username())
	if err != nil {
		t.Fatalf("decode generated userinfo: %v", err)
	}

	if got, want := string(decoded), "2022-blake3-aes-256-gcm:"+password; got != want {
		t.Fatalf("unexpected decoded userinfo: got %q want %q", got, want)
	}
}

func TestResolveSubscriptionUserAgent(t *testing.T) {
	tests := []struct {
		name         string
		subscription string
		globalUA     string
		wantUA       string
	}{
		{
			name:         "global user agent",
			subscription: "https://example.com/sub",
			globalUA:     "GlobalUA/1.0",
			wantUA:       "GlobalUA/1.0",
		},
		{
			name:         "fragment user agent overrides global",
			subscription: "https://example.com/sub#ua=Local%20UA%2F2.0&other=value",
			globalUA:     "GlobalUA/1.0",
			wantUA:       "Local UA/2.0",
		},
	}

	payload := base64.StdEncoding.EncodeToString([]byte("ss://example\n"))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &http.Client{
				Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
					if got := req.Header.Get("User-Agent"); got != tt.wantUA {
						t.Fatalf("User-Agent = %q, want %q", got, tt.wantUA)
					}
					if req.URL.Fragment != "" {
						t.Fatalf("URL fragment was not cleared: %q", req.URL.Fragment)
					}
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(payload)),
						Header:     make(http.Header),
						Request:    req,
					}, nil
				}),
			}

			_, nodes, err := ResolveSubscription(logrus.New(), client, t.TempDir(), tt.subscription, tt.globalUA)
			if err != nil {
				t.Fatalf("ResolveSubscription: %v", err)
			}
			if len(nodes) != 1 {
				t.Fatalf("len(nodes) = %d, want 1", len(nodes))
			}
		})
	}
}
