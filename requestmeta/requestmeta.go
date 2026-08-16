// SPDX-License-Identifier: MPL-2.0

// Package requestmeta resolves bounded request identity and reverse-proxy
// metadata once so security, logging, and application middleware agree.
package requestmeta

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

const maxForwardedHeader = 4096

var ErrInvalidForwarding = errors.New("requestmeta: invalid trusted forwarding metadata")

type contextKey struct{}

// Metadata is the normalized request identity shared by downstream packages.
type Metadata struct {
	RequestID      string
	ClientIP       netip.Addr
	ClientIPSource string
	ProxyPeerIP    netip.Addr
	ForwardedFor   string
	Scheme         string
	Host           string
}

// Config chooses the only peers whose forwarding metadata may affect identity.
type Config struct {
	TrustedProxies []netip.Prefix
	Random         io.Reader
	RequestIDBytes int
}

// Resolver is immutable and safe for concurrent use when Random is.
type Resolver struct {
	trusted []netip.Prefix
	random  io.Reader
	idBytes int
}

func New(config Config) (*Resolver, error) {
	if config.RequestIDBytes == 0 {
		config.RequestIDBytes = 16
	}
	if config.RequestIDBytes < 12 || config.RequestIDBytes > 32 {
		return nil, errors.New("requestmeta: request ID entropy must be 12 to 32 bytes")
	}
	if config.Random == nil {
		config.Random = rand.Reader
	}
	trusted := make([]netip.Prefix, len(config.TrustedProxies))
	for i, prefix := range config.TrustedProxies {
		if !prefix.IsValid() {
			return nil, fmt.Errorf("requestmeta: trusted proxy %d is invalid", i)
		}
		trusted[i] = prefix.Masked()
	}
	return &Resolver{trusted: trusted, random: config.Random, idBytes: config.RequestIDBytes}, nil
}

// Middleware fails closed before application code when entropy or trusted
// forwarding metadata is invalid.
func (resolver *Resolver) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		metadata, err := resolver.Resolve(request)
		if err != nil {
			response.Header().Set("Cache-Control", "no-store")
			status := http.StatusServiceUnavailable
			message := "request metadata unavailable"
			if errors.Is(err, ErrInvalidForwarding) {
				status = http.StatusBadRequest
				message = "invalid forwarding metadata"
			}
			http.Error(response, message, status)
			return
		}
		response.Header().Set("X-Request-ID", metadata.RequestID)
		next.ServeHTTP(response, request.WithContext(context.WithValue(request.Context(), contextKey{}, metadata)))
	})
}

// FromContext returns metadata installed by Middleware.
func FromContext(ctx context.Context) (Metadata, bool) {
	metadata, ok := ctx.Value(contextKey{}).(Metadata)
	return metadata, ok
}

func (resolver *Resolver) Resolve(request *http.Request) (Metadata, error) {
	requestID, err := resolver.requestID()
	if err != nil {
		return Metadata{}, fmt.Errorf("requestmeta: generate request ID: %w", err)
	}
	peer, err := peerAddress(request.RemoteAddr)
	if err != nil {
		return Metadata{}, err
	}
	if !validAuthority(request.Host) {
		return Metadata{}, ErrInvalidForwarding
	}
	metadata := Metadata{RequestID: requestID, ClientIP: peer, ClientIPSource: "peer", ProxyPeerIP: peer, Host: request.Host, Scheme: "http"}
	if request.TLS != nil {
		metadata.Scheme = "https"
	}
	if !resolver.isTrusted(peer) {
		return metadata, nil
	}

	forwardedFor := strings.Join(request.Header.Values("X-Forwarded-For"), ",")
	forwardedProto, protoOK := uniqueHeader(request.Header, "X-Forwarded-Proto")
	forwardedHost, hostOK := uniqueHeader(request.Header, "X-Forwarded-Host")
	if !protoOK || !hostOK {
		return Metadata{}, ErrInvalidForwarding
	}
	if len(forwardedFor) > maxForwardedHeader || len(forwardedProto) > 64 || len(forwardedHost) > 1024 {
		return Metadata{}, ErrInvalidForwarding
	}
	if forwardedFor != "" {
		chain, err := parseForwardedFor(forwardedFor)
		if err != nil {
			return Metadata{}, err
		}
		candidate := peer
		for index := len(chain) - 1; index >= 0 && resolver.isTrusted(candidate); index-- {
			candidate = chain[index]
		}
		metadata.ClientIP = candidate
		metadata.ClientIPSource = "forwarded"
		metadata.ForwardedFor = forwardedFor
	}
	if forwardedProto != "" {
		value, ok := singleForwardedValue(forwardedProto)
		if !ok || (value != "http" && value != "https") {
			return Metadata{}, ErrInvalidForwarding
		}
		metadata.Scheme = value
	}
	if forwardedHost != "" {
		value, ok := singleForwardedValue(forwardedHost)
		if !ok || !validAuthority(value) {
			return Metadata{}, ErrInvalidForwarding
		}
		metadata.Host = value
	}
	return metadata, nil
}

func (resolver *Resolver) requestID() (string, error) {
	value := make([]byte, resolver.idBytes)
	if _, err := io.ReadFull(resolver.random, value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}

func (resolver *Resolver) isTrusted(address netip.Addr) bool {
	for _, prefix := range resolver.trusted {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func peerAddress(remote string) (netip.Addr, error) {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		return netip.Addr{}, errors.New("requestmeta: remote address must contain host and port")
	}
	address, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, errors.New("requestmeta: remote address is invalid")
	}
	return address.Unmap(), nil
}

func parseForwardedFor(value string) ([]netip.Addr, error) {
	parts := strings.Split(value, ",")
	if len(parts) == 0 || len(parts) > 32 {
		return nil, ErrInvalidForwarding
	}
	result := make([]netip.Addr, 0, len(parts))
	for _, part := range parts {
		address, err := netip.ParseAddr(strings.TrimSpace(part))
		if err != nil || address.Zone() != "" {
			return nil, ErrInvalidForwarding
		}
		result = append(result, address.Unmap())
	}
	return result, nil
}

func singleForwardedValue(value string) (string, bool) {
	parts := strings.Split(value, ",")
	if len(parts) != 1 {
		return "", false
	}
	trimmed := strings.ToLower(strings.TrimSpace(parts[0]))
	return trimmed, trimmed != ""
}

func uniqueHeader(header http.Header, name string) (string, bool) {
	values := header.Values(name)
	if len(values) > 1 {
		return "", false
	}
	if len(values) == 0 {
		return "", true
	}
	return values[0], true
}

func validAuthority(value string) bool {
	return value != "" && len(value) <= 1024 && !strings.ContainsAny(value, "\\/\x00\r\n\t ,")
}
