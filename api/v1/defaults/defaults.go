package defaults

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	v1 "github.com/metal-stack/firewall-controller/api/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

type defaulter struct {
	log logr.Logger
}

func NewDefaulter(log logr.Logger) admission.CustomDefaulter {
	return &defaulter{
		log: log,
	}
}

func (d *defaulter) Default(ctx context.Context, obj runtime.Object) error {
	f, ok := obj.(*v1.ClusterwideNetworkPolicy)
	if !ok {
		return fmt.Errorf("mutator received unexpected type: %T", obj)
	}

	d.log.Info("defaulting resource", "name", f.GetName(), "namespace", f.GetNamespace())

	// TODO: Implement

	return nil
}
