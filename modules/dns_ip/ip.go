// Package dns_ip provides functionality to resolve IP addresses
// for a given domain using deterministic DNS resolution.
package dns_ip

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"cdua-org/ReconSR/schema"
)

var dnsServers = []string{
	"1.1.1.1:53",
	"1.0.0.1:53",
	"8.8.8.8:53",
	"8.8.4.4:53",
	"84.200.69.80:53",
	"84.200.70.40:53",
	"193.183.98.154:53",
	"185.121.177.177:53",
	"4.2.2.1:53",
	"4.2.2.2:53",
}

var dnsIndex atomic.Uint32

func getNextDNSServer() string {
	idx := dnsIndex.Add(1)
	//nolint:gosec // slice length is small and known
	pos := int(idx % uint32(len(dnsServers)))
	return dnsServers[pos]
}

func getCustomResolver() *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 3 * time.Second}
			return d.DialContext(ctx, "udp", getNextDNSServer())
		},
	}
}

type module struct{}

// New instantiates the module for registration within the dispatcher's lifecycle.
func New() schema.Module {
	return &module{}
}

// Name provides the unique identifier used by the dispatcher for routing.
func (m *module) Name() string {
	return "dns_ip"
}

// Capabilities declares the module's contract (inputs and functions) to the system core.
func (m *module) Capabilities() (schema.ModuleCapabilities, error) {
	return schema.ModuleCapabilities{
		Functions:  []string{"get_ip"},
		InputTypes: []string{"domain", "subdomain"},
	}, nil
}

// Exec acts as the stateless execution pipeline for incoming requests,
// isolating the core routing from the underlying network extraction logic.
func (m *module) Exec(data schema.ModuleInput) (schema.ModuleOutput, error) {
	executions := make([]schema.ModuleExecution, 0, len(data.Functions))

	for _, f := range data.Functions {
		var execution schema.ModuleExecution

		if f == "get_ip" {
			execution = getIPData(data.Target.Value)
		} else {
			errMsg := "unsupported function: " + f
			execution = schema.ModuleExecution{
				Function: f,
				Error:    &errMsg,
			}
		}

		executions = append(executions, execution)
	}

	return schema.ModuleOutput{
		Executions: executions,
	}, nil
}

func getIPData(target string) schema.ModuleExecution {
	execution := schema.ModuleExecution{
		Function: "get_ip",
		Results:  []schema.ModuleResult{},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resolver := getCustomResolver()

	ips, err := resolver.LookupIPAddr(ctx, target)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) {
			if dnsErr.IsNotFound || strings.Contains(err.Error(), "no such host") || strings.Contains(err.Error(), "server misbehaving") {
				return execution
			}
		}
		errMsg := "dns lookup failed: " + err.Error()
		execution.Error = &errMsg
		execution.Results = nil
		return execution
	}

	seen := make(map[string]bool)
	var resolvedIPs []string
	for _, ip := range ips {
		ipStr := ip.IP.String()
		if seen[ipStr] {
			continue
		}
		seen[ipStr] = true
		resolvedIPs = append(resolvedIPs, ipStr)

		execution.Results = append(execution.Results, schema.ModuleResult{
			Type:    "ip",
			Value:   ipStr,
			Context: "A/AAAA Record",
		})
	}

	if len(resolvedIPs) > 0 {
		execution.RawData = strings.Join(resolvedIPs, ", ")
	}

	return execution
}
