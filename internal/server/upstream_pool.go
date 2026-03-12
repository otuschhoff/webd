package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	mdns "github.com/miekg/dns"
)

const (
	dnsDefaultTTL       = 60 * time.Second
	dnsMinimumTTL       = 5 * time.Second
	dnsRefreshLeadMax   = 30 * time.Second
	dnsLookupTimeout    = 5 * time.Second
	dnsProbeTimeout     = 3 * time.Second
	dnsBackoffInitial   = 2 * time.Second
	dnsBackoffMax       = 2 * time.Minute
	dnsNoRecordsBackoff = 10 * time.Second
)

type resolvedEndpoint struct {
	address string
	ip      string
}

type upstreamPool struct {
	scheme     string
	hostname   string
	port       string
	serverName string
	rng        *rand.Rand

	resolver *systemDNSResolver

	mu          sync.Mutex
	cond        *sync.Cond
	refreshing  bool
	endpoints   []resolvedEndpoint
	refreshAt   time.Time
	nextLookup  time.Time
	lastErr     error
	backoff     time.Duration
	isLiteralIP bool
}

type systemDNSResolver struct {
	servers []string
	client  *mdns.Client
}

type upstreamTransport struct {
	base *http.Transport
	pool *upstreamPool
}

func newUpstreamPool(target *url.URL) (*upstreamPool, error) {
	host := target.Hostname()
	if host == "" {
		return nil, fmt.Errorf("upstream host is empty")
	}

	port := target.Port()
	if port == "" {
		switch strings.ToLower(target.Scheme) {
		case "http":
			port = "80"
		case "https":
			port = "443"
		default:
			return nil, fmt.Errorf("unsupported upstream scheme %q", target.Scheme)
		}
	}

	pool := &upstreamPool{
		scheme:   strings.ToLower(target.Scheme),
		hostname: host,
		port:     port,
		rng:      rand.New(rand.NewSource(time.Now().UnixNano())),
	}
	pool.cond = sync.NewCond(&pool.mu)

	if ip := net.ParseIP(host); ip != nil {
		pool.isLiteralIP = true
		pool.endpoints = []resolvedEndpoint{{
			ip:      ip.String(),
			address: net.JoinHostPort(ip.String(), port),
		}}
		return pool, nil
	}

	pool.serverName = host
	resolver, err := newSystemDNSResolver()
	if err != nil {
		return nil, err
	}
	pool.resolver = resolver
	pool.refreshAt = time.Now()
	pool.nextLookup = time.Now()
	return pool, nil
}

func newSystemDNSResolver() (*systemDNSResolver, error) {
	config, err := mdns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		return nil, fmt.Errorf("read /etc/resolv.conf: %w", err)
	}
	servers := make([]string, 0, len(config.Servers))
	for _, server := range config.Servers {
		servers = append(servers, net.JoinHostPort(server, config.Port))
	}
	if len(servers) == 0 {
		return nil, fmt.Errorf("no DNS servers configured in /etc/resolv.conf")
	}
	return &systemDNSResolver{
		servers: servers,
		client:  &mdns.Client{Net: "udp", Timeout: dnsLookupTimeout},
	}, nil
}

func newUpstreamTransport(pool *upstreamPool) http.RoundTripper {
	base := http.DefaultTransport.(*http.Transport).Clone()
	if pool.scheme == "https" {
		if base.TLSClientConfig == nil {
			base.TLSClientConfig = &tls.Config{}
		} else {
			base.TLSClientConfig = base.TLSClientConfig.Clone()
		}
		if pool.serverName != "" {
			base.TLSClientConfig.ServerName = pool.serverName
		}
	}
	return &upstreamTransport{base: base, pool: pool}
}

func (t *upstreamTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	endpoint, err := t.pool.selectEndpoint()
	if err != nil {
		return nil, err
	}

	clonedReq := req.Clone(req.Context())
	clonedURL := *req.URL
	clonedReq.URL = &clonedURL
	clonedReq.URL.Host = endpoint.address

	return t.base.RoundTrip(clonedReq)
}

func (p *upstreamPool) selectEndpoint() (resolvedEndpoint, error) {
	if p.isLiteralIP {
		return p.endpoints[0], nil
	}

	for {
		p.mu.Lock()
		now := time.Now()

		if len(p.endpoints) > 0 {
			if !p.refreshing && !now.Before(p.refreshAt) && !now.Before(p.nextLookup) {
				p.refreshing = true
				go p.refresh()
			}
			endpoint := p.endpoints[p.rng.Intn(len(p.endpoints))]
			p.mu.Unlock()
			return endpoint, nil
		}

		if !p.nextLookup.IsZero() && now.Before(p.nextLookup) && p.lastErr != nil {
			err := p.lastErr
			p.mu.Unlock()
			return resolvedEndpoint{}, err
		}

		if !p.refreshing {
			p.refreshing = true
			p.mu.Unlock()
			p.refresh()
			continue
		}

		p.cond.Wait()
		p.mu.Unlock()
	}
}

func (p *upstreamPool) refresh() {
	ctx, cancel := context.WithTimeout(context.Background(), dnsLookupTimeout+dnsProbeTimeout*time.Duration(4))
	defer cancel()

	endpoints, ttl, err := p.lookupAndValidate(ctx)
	now := time.Now()

	p.mu.Lock()
	defer func() {
		p.refreshing = false
		p.cond.Broadcast()
		p.mu.Unlock()
	}()

	if err != nil {
		p.lastErr = err
		if p.backoff <= 0 {
			p.backoff = dnsBackoffInitial
		} else {
			p.backoff *= 2
			if p.backoff > dnsBackoffMax {
				p.backoff = dnsBackoffMax
			}
		}
		p.nextLookup = now.Add(p.backoff)
		if len(p.endpoints) == 0 {
			p.refreshAt = p.nextLookup
		}
		log.Printf("dns refresh failed upstream_host=%q err=%v next_retry=%s cached_endpoints=%d", p.hostname, err, p.nextLookup.UTC().Format(time.RFC3339), len(p.endpoints))
		return
	}

	if len(endpoints) == 0 {
		p.lastErr = fmt.Errorf("dns refresh returned no healthy endpoints for %q", p.hostname)
		p.nextLookup = now.Add(dnsNoRecordsBackoff)
		if len(p.endpoints) == 0 {
			p.refreshAt = p.nextLookup
		}
		log.Printf("dns refresh failed upstream_host=%q err=%v next_retry=%s cached_endpoints=%d", p.hostname, p.lastErr, p.nextLookup.UTC().Format(time.RFC3339), len(p.endpoints))
		return
	}

	p.endpoints = endpoints
	p.lastErr = nil
	p.backoff = 0
	if ttl < dnsMinimumTTL {
		ttl = dnsMinimumTTL
	}
	refreshLead := ttl / 5
	if refreshLead <= 0 {
		refreshLead = time.Second
	}
	if refreshLead > dnsRefreshLeadMax {
		refreshLead = dnsRefreshLeadMax
	}
	if refreshLead >= ttl {
		refreshLead = ttl / 2
		if refreshLead <= 0 {
			refreshLead = time.Second
		}
	}
	p.refreshAt = now.Add(ttl - refreshLead)
	p.nextLookup = p.refreshAt
	log.Printf("dns refresh succeeded upstream_host=%q endpoints=%d ttl=%s refresh_at=%s", p.hostname, len(endpoints), ttl, p.refreshAt.UTC().Format(time.RFC3339))
}

func (p *upstreamPool) lookupAndValidate(ctx context.Context) ([]resolvedEndpoint, time.Duration, error) {
	ips, ttl, err := p.resolver.LookupIPAddrs(ctx, p.hostname)
	if err != nil {
		return nil, 0, err
	}

	working := make([]resolvedEndpoint, 0, len(ips))
	for _, ip := range ips {
		endpoint := resolvedEndpoint{
			ip:      ip.String(),
			address: net.JoinHostPort(ip.String(), p.port),
		}
		if probeErr := p.probeEndpoint(ctx, endpoint); probeErr != nil {
			log.Printf("dns endpoint rejected upstream_host=%q endpoint=%q err=%v", p.hostname, endpoint.address, probeErr)
			continue
		}
		working = append(working, endpoint)
	}

	if len(working) == 0 {
		return nil, ttl, fmt.Errorf("no healthy endpoints found for %q", p.hostname)
	}
	return working, ttl, nil
}

func (p *upstreamPool) probeEndpoint(ctx context.Context, endpoint resolvedEndpoint) error {
	dialer := &net.Dialer{Timeout: dnsProbeTimeout}

	switch p.scheme {
	case "http":
		conn, err := dialer.DialContext(ctx, "tcp", endpoint.address)
		if err != nil {
			return err
		}
		_ = conn.Close()
		return nil
	case "https":
		tlsConfig := &tls.Config{InsecureSkipVerify: true}
		if p.serverName != "" {
			tlsConfig.ServerName = p.serverName
		}
		conn, err := tls.DialWithDialer(dialer, "tcp", endpoint.address, tlsConfig)
		if err != nil {
			return err
		}
		_ = conn.Close()
		return nil
	default:
		return fmt.Errorf("unsupported scheme %q", p.scheme)
	}
}

func (r *systemDNSResolver) LookupIPAddrs(ctx context.Context, host string) ([]net.IP, time.Duration, error) {
	type queryResult struct {
		ips []net.IP
		ttl time.Duration
		err error
	}

	results := make([]queryResult, 0, 2)
	for _, qtype := range []uint16{mdns.TypeA, mdns.TypeAAAA} {
		ips, ttl, err := r.lookupOneType(ctx, host, qtype)
		if err == nil || len(ips) > 0 {
			results = append(results, queryResult{ips: ips, ttl: ttl})
			continue
		}
		results = append(results, queryResult{err: err})
	}

	dedup := make(map[string]struct{})
	ips := make([]net.IP, 0)
	ttl := time.Duration(0)
	var lastErr error
	for _, result := range results {
		if result.err != nil {
			lastErr = result.err
		}
		for _, ip := range result.ips {
			key := ip.String()
			if _, ok := dedup[key]; ok {
				continue
			}
			dedup[key] = struct{}{}
			ips = append(ips, ip)
		}
		if result.ttl > 0 && (ttl == 0 || result.ttl < ttl) {
			ttl = result.ttl
		}
	}

	if len(ips) == 0 {
		if lastErr == nil {
			lastErr = fmt.Errorf("no A/AAAA records found for %q", host)
		}
		return nil, 0, lastErr
	}
	if ttl <= 0 {
		ttl = dnsDefaultTTL
	}
	return ips, ttl, nil
}

func (r *systemDNSResolver) lookupOneType(ctx context.Context, host string, qtype uint16) ([]net.IP, time.Duration, error) {
	message := new(mdns.Msg)
	message.SetQuestion(mdns.Fqdn(host), qtype)
	message.RecursionDesired = true

	var lastErr error
	for _, server := range r.servers {
		response, _, err := r.client.ExchangeContext(ctx, message, server)
		if err != nil {
			lastErr = err
			continue
		}
		if response == nil {
			lastErr = fmt.Errorf("empty DNS response from %s", server)
			continue
		}
		if response.Rcode != mdns.RcodeSuccess {
			lastErr = fmt.Errorf("dns lookup failed for %q (%s): %s", host, mdns.TypeToString[qtype], mdns.RcodeToString[response.Rcode])
			continue
		}

		ips := make([]net.IP, 0, len(response.Answer))
		ttl := time.Duration(0)
		for _, answer := range response.Answer {
			switch rr := answer.(type) {
			case *mdns.A:
				ips = append(ips, rr.A)
				if rr.Hdr.Ttl > 0 {
					recordTTL := time.Duration(rr.Hdr.Ttl) * time.Second
					if ttl == 0 || recordTTL < ttl {
						ttl = recordTTL
					}
				}
			case *mdns.AAAA:
				ips = append(ips, rr.AAAA)
				if rr.Hdr.Ttl > 0 {
					recordTTL := time.Duration(rr.Hdr.Ttl) * time.Second
					if ttl == 0 || recordTTL < ttl {
						ttl = recordTTL
					}
				}
			}
		}
		return ips, ttl, nil
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("dns lookup failed for %q (%s)", host, mdns.TypeToString[qtype])
	}
	return nil, 0, lastErr
}
