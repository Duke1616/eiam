package sdk

import "testing"

func TestResolvePolicyPathWithPrefix(t *testing.T) {
	s := NewSDKWithURL("http://127.0.0.1:9000").WithPathPrefix("/api/plugin-runtime/builtin.ssh")

	if got := s.resolvePolicyPath("/sftp/delete"); got != "/api/plugin-runtime/builtin.ssh/sftp/delete" {
		t.Fatalf("unexpected resolved path: %s", got)
	}
	if got := s.resolvePolicyPath("/"); got != "/api/plugin-runtime/builtin.ssh" {
		t.Fatalf("unexpected root path: %s", got)
	}
}
