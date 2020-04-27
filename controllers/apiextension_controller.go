package controllers

import (
	"context"

	"github.com/go-logr/logr"
	apiextensionsv1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

// APIExtensionsReconciler reconciles a APIExtensions object
type APIExtensionsReconciler struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme
}

func (a APIExtensionsReconciler) APIExtension(crds apiextensionsv1beta1.CustomResourceDefinitionList) error {
	ctx := context.Background()
	log := a.Log.WithValues("apiextensions", "dunno")

	for _, crd := range crds.Items {
		obj := &apiextensionsv1beta1.CustomResourceDefinition{
			ObjectMeta: metav1.ObjectMeta{
				Name: crd.Name,
			},
		}

		if _, err := controllerutil.CreateOrUpdate(ctx, a.Client, &crd, func() error {
			existingCRD := obj
			existingCRD.Spec = crd.Spec
			log.Info("CRD created", "name", crd.Name)
			return nil
		}); err != nil {
			log.Error(err, "Error ensuring the CRD", "name", crd.Name)
		}
	}
	return nil
}
