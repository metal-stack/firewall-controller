package main

import (
	"testing"

	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
)

func Test_getSeedNamespace(t *testing.T) {
	tests := []struct {
		name          string
		want          string
		rawKubeconfig []byte
		wantErr       bool
	}{
		{
			name: "can extract seed namespace from current-context field",
			want: "example",
			rawKubeconfig: []byte(`apiVersion: v1
clusters:
- cluster:
    certificate-authority-data: foo
    server: server
    name: example
contexts:
- context:
    cluster: example
    user: example
    name: example
current-context: example
kind: Config
preferences: {}
users:
- name: example
  user:
  token: token`),
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getSeedNamespace(tt.rawKubeconfig)
			if (err != nil) != tt.wantErr {
				t.Errorf("getSeedNamespace() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("getSeedNamespace() = %v, want %v", got, tt.want)
			}
		})
	}
}
