package v1alpha1

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/go-logr/logr"
	workloadsv1alpha1 "github.com/gocardless/theatre/v5/api/workloads/v1alpha1"
	admissionv1 "k8s.io/api/admission/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// +kubebuilder:object:generate=false
type ConsoleAuthenticatorWebhook struct {
	reader            client.Reader
	lifecycleRecorder workloadsv1alpha1.LifecycleEventRecorder
	logger            logr.Logger
	decoder           admission.Decoder
}

// NewConsoleAuthenticatorWebhook builds the webhook that sets a new Console's
// user and enforces its template's creatorRules. reader should read from the
// API server rather than a cache, so a template's creatorRules take effect as
// soon as they're written.
func NewConsoleAuthenticatorWebhook(reader client.Reader, lifecycleRecorder workloadsv1alpha1.LifecycleEventRecorder, logger logr.Logger, scheme *runtime.Scheme) *ConsoleAuthenticatorWebhook {
	decoder := admission.NewDecoder(scheme)

	return &ConsoleAuthenticatorWebhook{
		reader:            reader,
		lifecycleRecorder: lifecycleRecorder,
		logger:            logger,
		decoder:           decoder,
	}
}

func (c *ConsoleAuthenticatorWebhook) Handle(ctx context.Context, req admission.Request) admission.Response {
	logger := c.logger.WithValues("uuid", string(req.UID))
	logger.Info("starting request", "event", "request.start")
	defer func(start time.Time) {
		logger.Info("completed request", "event", "request.end", "duration", time.Since(start).Seconds())
	}(time.Now())

	csl := &workloadsv1alpha1.Console{}
	if err := c.decoder.Decode(req, csl); err != nil {
		return admission.Errored(http.StatusBadRequest, err)
	}

	user := req.UserInfo.Username

	if req.Operation == admissionv1.Create {
		if resp, ok := c.checkCreatorRules(ctx, logger, req, csl); !ok {
			return resp
		}
	}

	copy := csl.DeepCopy()
	copy.Spec.User = user

	copyBytes, err := json.Marshal(copy)
	if err != nil {
		return admission.Errored(http.StatusInternalServerError, err)
	}

	logger.Info(fmt.Sprintf("authentication successful for user %s", user), "event", "authentication.success", "user", user)

	return admission.PatchResponseFromRaw(req.Object.Raw, copyBytes)
}

// checkCreatorRules denies the request unless the console's template allows
// the caller to create consoles from it. It fails closed: if the template
// can't be read, the console is rejected.
func (c *ConsoleAuthenticatorWebhook) checkCreatorRules(ctx context.Context, logger logr.Logger, req admission.Request, csl *workloadsv1alpha1.Console) (admission.Response, bool) {
	namespace := csl.Namespace
	if namespace == "" {
		namespace = req.Namespace
	}

	tpl := &workloadsv1alpha1.ConsoleTemplate{}
	key := client.ObjectKey{Namespace: namespace, Name: csl.Spec.ConsoleTemplateRef.Name}
	if err := c.reader.Get(ctx, key, tpl); err != nil {
		logger.Info("failed to get console template", "event", "authentication.failure", "template", key.Name, "error", err)
		return admission.Denied(fmt.Sprintf("failed to get console template %q to check its creatorRules: %v", key.Name, err)), false
	}

	username := req.UserInfo.Username
	if !tpl.AllowsCreator(username, req.UserInfo.Groups) {
		logger.Info("creator not allowed by template creatorRules", "event", "authentication.failure", "template", key.Name, "user", username)
		return admission.Denied(fmt.Sprintf(
			"user %q is not allowed to create consoles from template %q: it isn't listed in the template's creatorRules",
			username, key.Name,
		)), false
	}

	return admission.Response{}, true
}
