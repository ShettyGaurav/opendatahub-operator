//go:build !nowebhook

package v1

import (
	"context"
	"fmt"
	"net/http"
	"reflect"
	"strings"

	operatorv1 "github.com/openshift/api/operator/v1"
	admissionv1 "k8s.io/api/admission/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	dscv1 "github.com/opendatahub-io/opendatahub-operator/v2/api/datasciencecluster/v1"
	dscv2 "github.com/opendatahub-io/opendatahub-operator/v2/api/datasciencecluster/v2"
	"github.com/opendatahub-io/opendatahub-operator/v2/pkg/cluster/gvk"
	webhookutils "github.com/opendatahub-io/opendatahub-operator/v2/pkg/webhook"
)

//+kubebuilder:webhook:path=/validate-datasciencecluster-v1,matchPolicy=Exact,mutating=false,failurePolicy=fail,sideEffects=None,groups=datasciencecluster.opendatahub.io,resources=datascienceclusters,verbs=create;update,versions=v1,name=datasciencecluster-v1-validator.opendatahub.io,admissionReviewVersions=v1
//nolint:lll

// Validator implements webhook.AdmissionHandler for DataScienceCluster v1 validation webhooks.
// It enforces singleton creation rules, validates Kueue managementState, and always allows deletion.
type Validator struct {
	Client  client.Reader
	Name    string
	Decoder admission.Decoder
}

// Assert that Validator implements admission.Handler interface.
var _ admission.Handler = &Validator{}

// SetupWithManager registers the validating webhook with the provided controller-runtime manager.
//
// Parameters:
//   - mgr: The controller-runtime manager to register the webhook with.
//
// Returns:
//   - error: Always nil (for future extensibility).
func (v *Validator) SetupWithManager(mgr ctrl.Manager) error {
	hookServer := mgr.GetWebhookServer()
	hookServer.Register("/validate-datasciencecluster-v1", &webhook.Admission{
		Handler:        v,
		LogConstructor: webhookutils.NewWebhookLogConstructor(v.Name),
	})
	return nil
}

// Handle processes admission requests for create and update operations on DataScienceCluster v1 resources.
// It enforces singleton and managementState rules, allowing other operations by default.
//
// Parameters:
//   - ctx: Context for the admission request (logger is extracted from here).
//   - req: The admission.Request containing the operation and object details.
//
// Returns:
//   - admission.Response: The result of the admission check, indicating whether the operation is allowed or denied.
func (v *Validator) Handle(ctx context.Context, req admission.Request) admission.Response {
	log := logf.FromContext(ctx)
	ctx = logf.IntoContext(ctx, log)

	allowMessage := fmt.Sprintf("Operation %s on %s v1 allowed", req.Operation, req.Kind.Kind)

	if req.Kind.Kind != gvk.DataScienceClusterV1.Kind || req.Kind.Group != gvk.DataScienceClusterV1.Group || req.Kind.Version != gvk.DataScienceClusterV1.Version {
		err := fmt.Errorf("unexpected gvk: %v; expecting: %v", req.Kind, gvk.DataScienceClusterV1)
		logf.FromContext(ctx).Error(err, "got wrong group/version/kind")
		return admission.Errored(http.StatusBadRequest, err)
	}

	switch req.Operation {
	case admissionv1.Create:
		return validate(ctx, []validationCheck{v.denyKueueManagedState, denyMultipleDsc}, allowMessage, v.Client, &req)
	case admissionv1.Update:
		return validate(ctx, []validationCheck{v.denyKueueManagedState, v.denyV1PatchWhenV2ComponentsManaged}, allowMessage, v.Client, &req)
	default:
		return admission.Allowed(allowMessage)
	}
}

type validationCheck func(context.Context, client.Reader, *admission.Request) admission.Response

func validate(ctx context.Context, checks []validationCheck, allowedMessage string, cli client.Reader, request *admission.Request) admission.Response {
	for _, check := range checks {
		resp := check(ctx, cli, request)
		if !resp.Allowed {
			return resp
		}
	}

	return admission.Allowed(allowedMessage)
}

func denyMultipleDsc(ctx context.Context, cli client.Reader, req *admission.Request) admission.Response {
	return webhookutils.ValidateSingletonCreation(ctx, cli, req, gvk.DataScienceCluster)
}

func (v *Validator) denyKueueManagedState(ctx context.Context, _ client.Reader, req *admission.Request) admission.Response {
	dcsV1 := &dscv1.DataScienceCluster{}
	if err := v.Decoder.DecodeRaw(req.Object, dcsV1); err != nil {
		logf.FromContext(ctx).Error(err, "Error converting request object to "+gvk.DataScienceClusterV1.String())
		return admission.Errored(http.StatusBadRequest, err)
	}
	if dcsV1.Spec.Components.Kueue.ManagementState == operatorv1.Managed {
		return admission.Denied("Managed is no longer supported as a managementState")
	}

	return admission.Allowed("")
}

// denyV1PatchWhenV2ComponentsManaged prevents v1 API updates when v2-only components are Managed.
// This prevents data loss that would occur when v1 API (which doesn't have v2-only component fields)
// is used to update a DSC that has v2-only components set to Managed.
// During v1→v2 conversion, v2-only fields get default values (Removed), causing silent data loss.
func (v *Validator) denyV1PatchWhenV2ComponentsManaged(ctx context.Context, cli client.Reader, req *admission.Request) admission.Response {
	// Fetch the current DSC from cluster (stored as v2)
	currentDSC := &dscv2.DataScienceCluster{}
	if err := cli.Get(ctx, client.ObjectKey{Name: req.Name}, currentDSC); err != nil {
		// If not found, this is effectively a create - allow it
		if client.IgnoreNotFound(err) == nil {
			return admission.Allowed("")
		}
		logf.FromContext(ctx).Error(err, "Failed to get current DataScienceCluster for v2 component check")
		return admission.Errored(http.StatusInternalServerError, err)
	}

	// Check if any v2-only components are Managed
	v2OnlyComponents := getV2OnlyManagedComponents(currentDSC)

	if len(v2OnlyComponents) > 0 {
		// Build dynamic disable command for only the components that are actually Managed
		parts := make([]string, 0, len(v2OnlyComponents))
		for _, component := range v2OnlyComponents {
			parts = append(parts, fmt.Sprintf("\"%s\":{\"managementState\":\"Removed\"}", component))
		}
		disableCmd := fmt.Sprintf(
			"kubectl patch datasciencecluster.v2.datasciencecluster.opendatahub.io %s --type=merge "+
				"-p '{\"spec\":{\"components\":{%s}}}'",
			req.Name,
			strings.Join(parts, ","),
		)

		return admission.Denied(fmt.Sprintf(
			"cannot modify DataScienceCluster using v1 API: v2-only components are currently Managed: %v\n\n"+
				"Using v1 API would cause data loss because v2-only components (%s)\n"+
				"don't exist in v1 schema. During v1→v2 conversion, they would get default value 'Removed',\n"+
				"silently deleting your configuration.\n\n"+
				"To modify this resource, use the v2 API:\n"+
				"  kubectl patch datasciencecluster.v2.datasciencecluster.opendatahub.io %s --type=merge -p '<your-patch>'\n\n"+
				"Or first disable v2-only components using v2 API, then you can use v1 API:\n"+
				"  %s",
			v2OnlyComponents,
			strings.Join(v2OnlyComponents, ", "),
			req.Name,
			disableCmd,
		))
	}

	return admission.Allowed("")
}

// getV2OnlyManagedComponents dynamically finds components that exist in v2 but not v1,
// and returns those that are currently Managed.
// This uses reflection to automatically detect v2-only components without hardcoding,
// making it future-proof when new v2-only components are added.
func getV2OnlyManagedComponents(dsc *dscv2.DataScienceCluster) []string {
	managed := []string{}

	// Map of v2 field names that were renamed from v1
	// Key: v2 field name, Value: v1 field name
	renamedFields := map[string]string{
		"AIPipelines": "DataSciencePipelines", // v2's AIPipelines = v1's DataSciencePipelines
	}

	// Build a map of v1 component field names for comparison
	v1ComponentsType := reflect.TypeOf(dscv1.Components{})
	v1FieldNames := make(map[string]bool)
	for i := range v1ComponentsType.NumField() {
		v1FieldNames[v1ComponentsType.Field(i).Name] = true
	}

	// Examine v2 components to find v2-only ones
	v2ComponentsType := reflect.TypeOf(dsc.Spec.Components)
	v2ComponentsValue := reflect.ValueOf(dsc.Spec.Components)

	for i := range v2ComponentsType.NumField() {
		field := v2ComponentsType.Field(i)
		fieldName := field.Name

		// Skip if this component exists in v1 (not v2-only)
		if v1FieldNames[fieldName] {
			continue
		}

		// Check if this v2 field has a different name in v1 (renamed component)
		if v1EquivalentName, isRenamed := renamedFields[fieldName]; isRenamed {
			if v1FieldNames[v1EquivalentName] {
				continue // Component exists in v1 under a different name
			}
		}

		// This is a v2-only component - check if it's Managed
		componentValue := v2ComponentsValue.Field(i)

		// Get the ManagementState field using reflection
		managementStateField := componentValue.FieldByName("ManagementState")
		if !managementStateField.IsValid() {
			continue
		}

		// Check if ManagementState == Managed
		if managementStateField.Interface() == operatorv1.Managed {
			// Extract component name from JSON tag (e.g., `json:"trainer,omitempty"`)
			jsonTag := field.Tag.Get("json")
			componentName := strings.Split(jsonTag, ",")[0]
			if componentName != "" && componentName != "-" {
				managed = append(managed, componentName)
			}
		}
	}

	return managed
}
