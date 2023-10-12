package updater

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	firewallv2 "github.com/metal-stack/firewall-controller-manager/api/v2"
	firewallv1 "github.com/metal-stack/firewall-controller/v2/api/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/record"
)

// ShootRecorderNamespaceRewriter returns a function to record an event in the shoot cluster for a firewall v2 resource.
// Before recording the event we rewrite the firewall resource's namespace because the firewall v2 resource resides in the seed namespace
// which does not exist in the shoot, so we need to alter it to the firewall namespace in the shoot.
func ShootRecorderNamespaceRewriter(shootRecorder record.EventRecorder) func(f *firewallv2.Firewall, eventtype, reason, message string) {
	return func(f *firewallv2.Firewall, eventtype, reason, message string) {
		copy := f.DeepCopy()
		copy.Namespace = firewallv1.ClusterwideNetworkPolicyNamespace
		shootRecorder.Event(copy, eventtype, reason, message)
	}
}

type Updater struct {
	log logr.Logger

	recorderCallback func(f *firewallv2.Firewall, eventtype, reason, message string)
}

func New(log logr.Logger, shootRecorder record.EventRecorder) *Updater {
	return &Updater{
		log:              log,
		recorderCallback: ShootRecorderNamespaceRewriter(shootRecorder),
	}
}

func (u *Updater) Run(ctx context.Context, f *firewallv2.Firewall) error {
	err := u.updateFirewallController(f)
	if err != nil {
		u.recorderCallback(f, corev1.EventTypeWarning, "Self-Reconcilation", fmt.Sprintf("updating firewall-controller failed with error: %v", err))
		return err
	}

	err = u.updateNFTablesExporter(ctx, f)
	if err != nil {
		u.recorderCallback(f, corev1.EventTypeWarning, "Self-Reconcilation", fmt.Sprintf("updating nftables-exporter failed with error: %v", err))
		return err
	}

	return nil
}
