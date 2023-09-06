package validation

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	v1 "github.com/metal-stack/firewall-controller/api/v1"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	apivalidation "k8s.io/apimachinery/pkg/api/validation"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

type Validator struct {
	log logr.Logger
}

func NewValidator(log logr.Logger) *Validator {
	return &Validator{
		log: log,
	}
}

func (v *Validator) ValidateCreate(ctx context.Context, obj runtime.Object) error {
	var (
		o, ok   = obj.(*v1.ClusterwideNetworkPolicy)
		allErrs field.ErrorList
	)

	if !ok {
		return apierrors.NewBadRequest(fmt.Sprintf("validator received unexpected type: %T", obj))
	}

	accessor, err := meta.Accessor(obj)
	if err != nil {
		return apierrors.NewBadRequest(fmt.Sprintf("failed to get accessor for object: %s", err))
	}

	v.log.Info("validating resource creation", "name", accessor.GetName(), "namespace", accessor.GetNamespace())

	allErrs = append(allErrs, apivalidation.ValidateObjectMetaAccessor(accessor, true, apivalidation.NameIsDNSSubdomain, field.NewPath("metadata"))...)
	allErrs = append(allErrs, validateCreate(o)...)

	if len(allErrs) == 0 {
		return nil
	}

	return apierrors.NewInvalid(
		obj.GetObjectKind().GroupVersionKind().GroupKind(),
		accessor.GetName(),
		allErrs,
	)
}

func validateCreate(cwnp *v1.ClusterwideNetworkPolicy) field.ErrorList {
	var allErrs field.ErrorList

	// TODO: implement

	return allErrs
}

func (v *Validator) ValidateUpdate(ctx context.Context, oldObj, newObj runtime.Object) error {
	var (
		oldO, oldOk = oldObj.(*v1.ClusterwideNetworkPolicy)
		newO, newOk = newObj.(*v1.ClusterwideNetworkPolicy)
		allErrs     field.ErrorList
	)

	if !oldOk {
		return apierrors.NewBadRequest(fmt.Sprintf("validator received unexpected type: %T", oldO))
	}
	if !newOk {
		return apierrors.NewBadRequest(fmt.Sprintf("validator received unexpected type: %T", newO))
	}

	oldAccessor, err := meta.Accessor(oldO)
	if err != nil {
		return apierrors.NewBadRequest(fmt.Sprintf("failed to get accessor for object: %s", err))
	}
	newAccessor, err := meta.Accessor(newO)
	if err != nil {
		return apierrors.NewBadRequest(fmt.Sprintf("failed to get accessor for object: %s", err))
	}

	v.log.Info("validating resource update", "name", newAccessor.GetName(), "namespace", newAccessor.GetNamespace())

	allErrs = append(allErrs, apivalidation.ValidateObjectMetaAccessorUpdate(newAccessor, oldAccessor, field.NewPath("metadata"))...)
	allErrs = append(allErrs, validateUpdate(oldO, newO)...)

	if len(allErrs) == 0 {
		return nil
	}

	return apierrors.NewInvalid(
		newO.GetObjectKind().GroupVersionKind().GroupKind(),
		newAccessor.GetName(),
		allErrs,
	)
}

func validateUpdate(old, new *v1.ClusterwideNetworkPolicy) field.ErrorList {
	var allErrs field.ErrorList

	// TODO: implement

	return allErrs
}

// Validates ClusterwideNetworkPolicy object
// +kubebuilder:rbac:groups=metal-stack.io,resources=clusterwidenetworkpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=metal-stack.io,resources=clusterwidenetworkpolicies/status,verbs=get;update;patch
// func (r *ClusterwideNetworkPolicyValidationReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
// 	var clusterNP firewallv1.ClusterwideNetworkPolicy
// 	if err := r.ShootClient.Get(ctx, req.NamespacedName, &clusterNP); err != nil {
// 		return ctrl.Result{}, client.IgnoreNotFound(err)
// 	}

// 	// if network policy does not belong to the namespace where clusterwide network policies are stored:
// 	// update status with error message
// 	if req.Namespace != firewallv1.ClusterwideNetworkPolicyNamespace {
// 		r.Recorder.Event(
// 			&clusterNP,
// 			corev1.EventTypeWarning,
// 			"Unapplicable",
// 			fmt.Sprintf("cluster wide network policies must be defined in namespace %s otherwise they won't take effect", firewallv1.ClusterwideNetworkPolicyNamespace),
// 		)
// 		return ctrl.Result{}, nil
// 	}

// 	err := clusterNP.Spec.Validate()
// 	if err != nil {
// 		r.Recorder.Event(
// 			&clusterNP,
// 			corev1.EventTypeWarning,
// 			"Unapplicable",
// 			fmt.Sprintf("cluster wide network policy is not valid: %v", err),
// 		)
// 		return ctrl.Result{}, nil
// 	}

// 	return ctrl.Result{}, nil
// }

// // Validate validates the spec of a ClusterwideNetworkPolicy
// func (p *PolicySpec) Validate() error {
// 	var errs []error
// 	for _, e := range p.Egress {
// 		errs = append(errs, validatePorts(e.Ports), validateIPBlocks(e.To))
// 	}
// 	for _, i := range p.Ingress {
// 		errs = append(errs, validatePorts(i.Ports), validateIPBlocks(i.From))
// 	}

// 	return errors.Join(errs...)
// }

// func validatePorts(ports []networking.NetworkPolicyPort) error {
// 	var errs []error
// 	for _, p := range ports {
// 		if p.Port != nil && p.Port.Type != intstr.Int {
// 			errs = append(errs, fmt.Errorf("only int ports are supported, but %v given", p.Port))
// 		}

// 		if p.Port != nil && (p.Port.IntValue() > 65535 || p.Port.IntValue() <= 0) {
// 			errs = append(errs, fmt.Errorf("only ports between 0 and 65535 are allowed, but %v given", p.Port))
// 		}

// 		if p.Protocol != nil {
// 			proto := *p.Protocol
// 			if proto != corev1.ProtocolUDP && proto != corev1.ProtocolTCP {
// 				errs = append(errs, fmt.Errorf("only TCP and UDP are supported as protocol, but %v given", proto))
// 			}
// 		}
// 	}
// 	return errors.Join(errs...)
// }

// func validateIPBlocks(blocks []networking.IPBlock) error {
// 	var errs []error
// 	for _, b := range blocks {
// 		_, blockNet, err := net.ParseCIDR(b.CIDR)
// 		if err != nil {
// 			errs = append(errs, fmt.Errorf("%v is not a valid IP CIDR", b.CIDR))
// 			continue
// 		}

// 		for _, e := range b.Except {
// 			exceptIP, exceptNet, err := net.ParseCIDR(b.CIDR)
// 			if err != nil {
// 				errs = append(errs, fmt.Errorf("%v is not a valid IP CIDR", e))
// 				continue
// 			}

// 			if !blockNet.Contains(exceptIP) {
// 				errs = append(errs, fmt.Errorf("%v is not contained in the IP CIDR %v", exceptIP, blockNet))
// 				continue
// 			}

// 			blockSize, _ := blockNet.Mask.Size()
// 			exceptSize, _ := exceptNet.Mask.Size()
// 			if exceptSize > blockSize {
// 				errs = append(errs, fmt.Errorf("netmask size of network to be excluded must be smaller than netmask of the block CIDR"))
// 			}
// 		}
// 	}
// 	return errors.Join(errs...)
// }

func (_ *Validator) ValidateDelete(ctx context.Context, obj runtime.Object) error {
	return nil
}
