package leakix

import (
	"encoding/json"
)

func parseLeakixResponse(rawBody []byte) (*Response, error) {
	var resp Response
	if err := json.Unmarshal(rawBody, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}
