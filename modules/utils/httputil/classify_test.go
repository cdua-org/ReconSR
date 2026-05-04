package httputil

import "testing"

func TestClassifyStatus(t *testing.T) {
	tests := []struct {
		code int
		want ResponseAction
	}{

		{400, Abort},
		{401, Abort},
		{403, Abort},
		{404, Abort},
		{405, Abort},
		{406, Abort},
		{407, Abort},
		{409, Abort},
		{410, Abort},
		{411, Abort},
		{412, Abort},
		{413, Abort},
		{414, Abort},
		{415, Abort},
		{422, Abort},
		{451, Abort},

		{418, Abort},
		{499, Abort},

		{408, Retry},     // Request Timeout → transient
		{429, RateLimit}, // Too Many Requests → backoff

		{500, Retry},
		{502, Retry},
		{503, Retry},
		{504, Retry},
		{507, Retry},
		{599, Retry}, // unlisted 5xx

		{520, Retry},
		{521, Retry},
		{525, Retry},
		{530, Retry},

		{399, Abort}, // 3xx is not an error — safe default
		{200, Abort}, // 2xx should not be classified but safe default
	}

	for _, tt := range tests {
		got := ClassifyStatus(tt.code)
		if got != tt.want {
			t.Errorf("ClassifyStatus(%d) = %d, want %d", tt.code, got, tt.want)
		}
	}
}
