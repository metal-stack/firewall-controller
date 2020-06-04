package collector

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCollect(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, metrics)
	}))
	defer ts.Close()

	c := NewNodeExporterCollector(nil, ts.URL)

	ds, err := c.Collect()
	require.Nil(t, err)
	require.NotNil(t, ds)
	for device, stats := range *ds {
		t.Logf("device:%s, %v\n", device, stats)
	}
	// t.Fail()
}
