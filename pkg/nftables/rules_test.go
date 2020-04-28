package nftables

import (
	"testing"

	"io/ioutil"
	"log"

	"github.com/ghodss/yaml"
)

func TestHasChanged(t *testing.T) {
	tt := []struct {
		name string
		old  *FirewallRules
		new  *FirewallRules
		want bool
	}{
		{
			name: "initialization",
			old:  nil,
			new:  &FirewallRules{},
			want: true,
		},
		{
			name: "empty rule set to empty rule set",
			old:  &FirewallRules{},
			new:  &FirewallRules{},
			want: false,
		},
		{
			name: "changes of rules",
			old: &FirewallRules{
				IngressRules: []string{"allow ingress 1"},
			},
			new: &FirewallRules{
				IngressRules: []string{"allow ingress 2"},
			},
			want: true,
		},
		{
			name: "equal rules",
			old: &FirewallRules{
				IngressRules: []string{"allow ingress 1", "allow ingress 2"},
			},
			new: &FirewallRules{
				IngressRules: []string{"allow ingress 1", "allow ingress 2"},
			},
			want: false,
		},
		{
			name: "rule deletion",
			old: &FirewallRules{
				IngressRules: []string{"allow ingress 1"},
			},
			new: &FirewallRules{
				IngressRules: []string{},
			},
			want: true,
		},
		{
			name: "rule addition",
			old: &FirewallRules{
				IngressRules: []string{},
			},
			new: &FirewallRules{
				IngressRules: []string{"allow ingress 1"},
			},
			want: true,
		},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.new.HasChanged(tc.old)
			if got != tc.want {
				t.Errorf("got: %v, wanted: %v, old: %v, new: %v", got, tc.want, tc.old, tc.new)
			}
		})
	}
}

// won't work because crd is not deployed
// func TestFetchAndAssembleWithTestData(t *testing.T) {
// 	for _, tc := range list("test_data", true) {
// 		t.Run(tc, func(t *testing.T) {
// 			tcd := path.Join("test_data", tc)
// 			c := testclient.NewSimpleClientset()
// 			for _, i := range list(path.Join(tcd, "services"), false) {
// 				var svc corev1.Service
// 				mustUnmarshal(path.Join(tcd, "services", i), &svc)
// 				_, err := c.CoreV1().Services(svc.ObjectMeta.Namespace).Create(&svc)
// 				assert.Nil(t, err)
// 			}
// 			for _, i := range list(path.Join(tcd, "policies"), false) {
// 				var np firewallv1.ClusterwideNetworkPolicy
// 				mustUnmarshal(path.Join(tcd, "policies", i), &np)
// 				_, err := c.NetworkingV1().NetworkPolicies(np.ObjectMeta.Namespace).Create(&np)
// 				assert.Nil(t, err)
// 			}
// 			controller := NewFirewallController(c, nil)
// 			rules, err := controller.FetchAndAssemble()
// 			if err != nil {
// 				panic(err)
// 			}
// 			exp, _ := ioutil.ReadFile(path.Join(tcd, "expected.nftablev4"))
// 			rs, err := rules.Render()
// 			assert.Nil(t, err)
// 			assert.Equal(t, string(exp), rs)
// 		})
// 	}
// }

func list(path string, dirs bool) []string {
	files, err := ioutil.ReadDir(path)
	if err != nil {
		log.Fatal(err)
	}
	r := []string{}
	for _, f := range files {
		if f.IsDir() && dirs {
			r = append(r, f.Name())
		} else if !f.IsDir() && !dirs {
			r = append(r, f.Name())
		}
	}
	return r
}

func mustUnmarshal(f string, data interface{}) {
	c, _ := ioutil.ReadFile(f)
	err := yaml.Unmarshal(c, data)
	if err != nil {
		panic(err)
	}
}
