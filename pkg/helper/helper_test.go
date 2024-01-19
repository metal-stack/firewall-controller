package helper

import (
	"net/netip"
	"testing"

	"go4.org/netipx"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func helpMustParseIPSet(ips []string) *netipx.IPSet {
	res, _ := BuildNetworksIPSet(ips)
	return res
}

func TestBuildNetworksIPSet(t *testing.T) {
	type args struct {
		networks []string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "legal values",
			args: args{
				networks: []string{
					"192.168.0.0/16",
					"1.2.3.4/24",
				},
			},
			wantErr: false,
		},
		{
			name: "overlapping values",
			args: args{
				networks: []string{
					"192.168.0.0/16",
					"192.168.1.0/8",
				},
			},
			wantErr: false,
		},
		{
			name: "illegal IP",
			args: args{
				networks: []string{
					"292.168.0.0/16",
					"192.168.1.0/8",
				},
			},
			wantErr: true,
		},
		{
			name: "illegal mask",
			args: args{
				networks: []string{
					"192.168.0.0/33",
					"192.168.1.0/8",
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := BuildNetworksIPSet(tt.args.networks)
			if (err != nil) != tt.wantErr {
				t.Errorf("BuildNetworksIPSet() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != nil {
				for _, n := range tt.args.networks {
					p, _ := netip.ParsePrefix(n)
					if !got.ContainsPrefix(p) {
						t.Errorf("BuildNetworksIPSet() = does not contain %v", p)
					}
				}
			}
		})
	}
}

func TestNetworkSetAsString(t *testing.T) {
	type args struct {
		externalSet *netipx.IPSet
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "list of overlapping ranges",
			args: args{
				externalSet: helpMustParseIPSet([]string{"192.168.0.1/8", "192.168.1.1/16"}),
			},
			want: "192.0.0.0/8",
		},
		{
			name: "list of non overlapping ranges",
			args: args{
				externalSet: helpMustParseIPSet([]string{"192.168.1.1/24", "192.168.2.1/24"}),
			},
			want: "192.168.1.0-192.168.2.255",
		},
		{
			name: "list of ranges",
			args: args{
				externalSet: helpMustParseIPSet([]string{"192.168.1.1/24", "193.168.2.1/24"}),
			},
			want: "192.168.1.0/24,193.168.2.0/24",
		},
		{
			name: "list of ranges with single IP-cidr",
			args: args{
				externalSet: helpMustParseIPSet([]string{"192.168.1.1/24", "193.168.2.1/24", "1.2.3.4/32"}),
			},
			want: "1.2.3.4/32,192.168.1.0/24,193.168.2.0/24",
		},
		{
			name: "empty input",
			args: args{
				externalSet: nil,
			},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NetworkSetAsString(tt.args.externalSet); got != tt.want {
				t.Errorf("NetworkSetAsString() = %v, want %v", got, tt.want)
			}
		})
	}
}

type mockRecorder struct {
	evType   string
	evReason string
	tpreason string
	ok       bool
	invoke   bool
}

func (mr *mockRecorder) Event(object runtime.Object, eventtype, reason, message string) {
	mr.invoke = true
	mr.tpreason = eventtype + "," + reason
	mr.ok = eventtype == mr.evType && reason == mr.evReason
}
func (mr *mockRecorder) Eventf(object runtime.Object, eventtype, reason, messageFmt string, args ...interface{}) {
	mr.invoke = true
	mr.tpreason = eventtype + "," + reason
	mr.ok = eventtype == mr.evType && reason == mr.evReason
}
func (mr *mockRecorder) AnnotatedEventf(object runtime.Object, annotations map[string]string, eventtype, reason, messageFmt string, args ...interface{}) {
	mr.invoke = true
	mr.tpreason = eventtype + "," + reason
	mr.ok = eventtype == mr.evType && reason == mr.evReason
}

func TestValidateCIDR(t *testing.T) {
	type args struct {
		o     runtime.Object
		cidr  string
		ipset *netipx.IPSet
	}
	tests := []struct {
		name            string
		args            args
		want            bool
		wantRecordEvent bool
		wantErr         bool
	}{
		{
			name: "cidr in ipset",
			args: args{
				o:     nil,
				cidr:  "192.168.0.6/24",
				ipset: helpMustParseIPSet([]string{"192.168.0.0/16"}),
			},
			want:            true,
			wantRecordEvent: false,
			wantErr:         false,
		},
		{
			name: "cidr not in ipset",
			args: args{
				o:     nil,
				cidr:  "193.168.0.6/24",
				ipset: helpMustParseIPSet([]string{"192.168.0.0/16"}),
			},
			want:            false,
			wantRecordEvent: true,
			wantErr:         false,
		},
		{
			name: "illegal cidr value",
			args: args{
				o:     nil,
				cidr:  "293.168.0.6/24",
				ipset: helpMustParseIPSet([]string{"192.168.0.0/16"}),
			},
			want:            false,
			wantRecordEvent: false,
			wantErr:         true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := mockRecorder{evType: corev1.EventTypeWarning, evReason: forbiddenCIDR}

			got, err := ValidateCIDR(tt.args.o, tt.args.cidr, tt.args.ipset, &rec)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateCIDR() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ValidateCIDR() = %v, want %v", got, tt.want)
			}
			if tt.wantRecordEvent != rec.invoke {
				t.Errorf("ValidateCIDR() log event = %v, wanted log event %v", rec.invoke, tt.wantRecordEvent)
			}
			if tt.wantRecordEvent && !rec.ok {
				t.Errorf("ValidateCIDR() did log wrong type/reason %q", rec.tpreason)
			}

		})
	}
}
