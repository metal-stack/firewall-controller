package nftables

import (
	"reflect"
	"testing"
)

func Test_diff(t *testing.T) {
	tests := []struct {
		name    string
		desired []string
		current []string
		want    diffResult
	}{
		{
			name:    "simple",
			desired: []string{"1.2.3.4"},
			current: []string{"8.8.8.8"},
			want: diffResult{
				toAdd:    []string{"1.2.3.4"},
				toRemove: []string{"8.8.8.8"},
			},
		},
		{
			name:    "advanced",
			desired: []string{"1.2.3.4", "1.2.3.5", "1.2.3.6"},
			current: []string{"8.8.8.8", "4.4.4.4", "1.2.3.6"},
			want: diffResult{
				toAdd:    []string{"1.2.3.4", "1.2.3.5"},
				toRemove: []string{"8.8.8.8", "4.4.4.4"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := diff(tt.desired, tt.current); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("diff() = %v, want %v", got, tt.want)
			}
		})
	}
}
