package erc8004

import "testing"

// NewClient's HTTP client has a timeout.
func TestNewClientTimesOut(t *testing.T) {
	if timeout := NewClient("http://api").http.Timeout; timeout <= 0 {
		t.Errorf("the client's timeout is %v", timeout)
	}
}
