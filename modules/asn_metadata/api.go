// Package asn_metadata provides ASN intelligence via RIPE RIPEstat API.
package asn_metadata

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"cdua-org/ReconSR/modules/utils/resolver"
)

const (
	ripeStatHost = "https://stat.ripe.net"
)

type ripeAPIResponse struct {
	RawJSON string `json:"-"`
	Data    struct {
		Neighbours []neighbour `json:"neighbours"`
	} `json:"data"`
	NeighbourCounts struct {
		Left   int `json:"left"`
		Right  int `json:"right"`
		Unique int `json:"unique"`
	} `json:"neighbour_counts"`
}

type neighbour struct {
	Position  string `json:"type"`
	ASN       int    `json:"asn"`
	PathCount int    `json:"power"`
	PeerCount int    `json:"v4_peers"`
}

func attemptRIPEstatQuery(ctx context.Context, url, resource, endpoint string, result any, debug bool, attempt int) error {
	reqCtx, cancel := context.WithTimeout(ctx, resolver.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: resolver.HTTPTimeout}
	resp, err := client.Do(req)
	if err != nil {
		if debug {
			fmt.Fprintf(os.Stderr, "[asn_meta-debug] queryRIPEstat attempt=%d resource=%q endpoint=%q err=%v\n", attempt, resource, endpoint, err)
		}
		return fmt.Errorf("ripestat request failed: %w", err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil && isDebug() {
			fmt.Fprintf(os.Stderr, "[asn_meta-debug] body close: %v\n", cerr)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		if debug {
			fmt.Fprintf(os.Stderr, "[asn_meta-debug] queryRIPEstat attempt=%d resource=%q endpoint=%q status=%d\n", attempt, resource, endpoint, resp.StatusCode)
		}
		return fmt.Errorf("http status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		if debug {
			fmt.Fprintf(os.Stderr, "[asn_meta-debug] queryRIPEstat attempt=%d resource=%q endpoint=%q read_error=%v\n", attempt, resource, endpoint, err)
		}
		return fmt.Errorf("read body: %w", err)
	}

	if rr, ok := result.(*ripeAPIResponse); ok {
		rr.RawJSON = string(body)
	}
	if err := json.Unmarshal(body, result); err != nil {
		if debug {
			fmt.Fprintf(os.Stderr, "[asn_meta-debug] queryRIPEstat attempt=%d resource=%q endpoint=%q unmarshal_error=%v\n", attempt, resource, endpoint, err)
		}
		return fmt.Errorf("unmarshal: %w", err)
	}

	if debug {
		fmt.Fprintf(os.Stderr, "[asn_meta-debug] queryRIPEstat attempt=%d resource=%q endpoint=%q success\n", attempt, resource, endpoint)
	}
	return nil
}

func queryRIPEstat(ctx context.Context, resource, endpoint string, result any) error {
	url := fmt.Sprintf("%s/data/%s/data.json?resource=%s", ripeStatHost, endpoint, resource)
	debug := isDebug()

	var lastErr error

	for attempt := 1; attempt <= resolver.MaxRetriesASNMeta; attempt++ {
		err := attemptRIPEstatQuery(ctx, url, resource, endpoint, result, debug, attempt)
		if err == nil {
			return nil
		}
		lastErr = err
	}

	return fmt.Errorf("all attempts failed: %w", lastErr)
}

func isDebug() bool {
	val, ok := resolver.GetOption("Debug")
	return ok && val == "true"
}

func normalizeASN(asn string) string {
	asn = strings.TrimSpace(asn)
	if asn == "" {
		return ""
	}
	asn = strings.ToUpper(asn)
	if !strings.HasPrefix(asn, "AS") {
		asn = "AS" + asn
	}
	for _, c := range asn[2:] {
		if c < '0' || c > '9' {
			return ""
		}
	}
	return asn
}
