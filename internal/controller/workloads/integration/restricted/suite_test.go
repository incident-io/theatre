// Package restricted runs the console controller with --approvers-without-exec
// and --subjects-without-access set, and plain RoleBindings so the API server's
// RBAC authoriser can answer what each subject is allowed to do.
package restricted

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	rbacv1alpha1 "github.com/gocardless/theatre/v5/api/rbac/v1alpha1"
	workloadsv1alpha1 "github.com/gocardless/theatre/v5/api/workloads/v1alpha1"
	consolecontroller "github.com/gocardless/theatre/v5/internal/controller/workloads"
	internalworkloadsv1alpha1 "github.com/gocardless/theatre/v5/internal/webhook/workloads/v1alpha1"
	"github.com/gocardless/theatre/v5/pkg/workloads/console/events"
)

const authoriserUsername = "system:serviceaccount:theatre-system:console-authoriser"

var (
	mgr     ctrl.Manager
	testEnv *envtest.Environment
	ctx     context.Context
	cancel  context.CancelFunc
)

func TestSuite(t *testing.T) {
	SetDefaultEventuallyTimeout(5 * time.Second)
	RegisterFailHandler(Fail)
	RunSpecs(t, "controllers/workloads/integration/restricted")
}

var _ = BeforeSuite(func() {
	logf.SetLogger(zap.New(zap.UseDevMode(true), zap.WriteTo(GinkgoWriter)))

	ctx, cancel = context.WithCancel(context.Background())

	By("bootstrapping test environment")
	configDir := filepath.Join("..", "..", "..", "..", "..", "config")
	testEnv = &envtest.Environment{
		CRDDirectoryPaths: []string{filepath.Join(configDir, "crd", "bases")},
		WebhookInstallOptions: envtest.WebhookInstallOptions{
			Paths: []string{filepath.Join(configDir, "base", "webhooks")},
		},
	}

	cfg, err := testEnv.Start()
	Expect(err).ToNot(HaveOccurred())
	Expect(cfg).ToNot(BeNil())

	scheme := runtime.NewScheme()
	Expect(clientgoscheme.AddToScheme(scheme)).To(Succeed())
	Expect(rbacv1alpha1.AddToScheme(scheme)).To(Succeed())
	Expect(workloadsv1alpha1.AddToScheme(scheme)).To(Succeed())

	idBuilder := workloadsv1alpha1.NewConsoleIdBuilder("test")
	lifecycleRecorder := workloadsv1alpha1.NewLifecycleEventRecorder("test", ctrl.Log, events.NewNopPublisher(), idBuilder)

	server := webhook.NewServer(webhook.Options{
		Host:    testEnv.WebhookInstallOptions.LocalServingHost,
		CertDir: testEnv.WebhookInstallOptions.LocalServingCertDir,
		Port:    testEnv.WebhookInstallOptions.LocalServingPort,
	})

	mgr, err = ctrl.NewManager(cfg, ctrl.Options{
		Scheme:        scheme,
		WebhookServer: server,
		Metrics: metricsserver.Options{
			BindAddress: "0",
		},
	})
	Expect(err).ToNot(HaveOccurred())

	mgr.GetWebhookServer().Register("/mutate-consoles", &admission.Webhook{
		Handler: internalworkloadsv1alpha1.NewConsoleAuthenticatorWebhook(
			lifecycleRecorder,
			ctrl.Log.WithName("webhooks").WithName("console-authenticator"),
			mgr.GetScheme(),
		),
	})
	mgr.GetWebhookServer().Register("/validate-consoleauthorisations", &admission.Webhook{
		Handler: internalworkloadsv1alpha1.NewConsoleAuthorisationWebhook(
			mgr.GetClient(),
			lifecycleRecorder,
			ctrl.Log.WithName("webhooks").WithName("console-authorisation"),
			mgr.GetScheme(),
		),
	})
	mgr.GetWebhookServer().Register("/validate-consoletemplates", &admission.Webhook{
		Handler: internalworkloadsv1alpha1.NewConsoleTemplateValidationWebhook(
			ctrl.Log.WithName("webhooks").WithName("console-template"),
			mgr.GetScheme(),
		),
	})

	err = (&consolecontroller.ConsoleReconciler{
		Client:                mgr.GetClient(),
		LifecycleRecorder:     lifecycleRecorder,
		Log:                   ctrl.Log.WithName("controllers").WithName("console"),
		Scheme:                mgr.GetScheme(),
		ConsoleIdBuilder:      idBuilder,
		ApproversWithoutExec:  true,
		SubjectsWithoutAccess: []string{authoriserUsername},
	}).SetupWithManager(ctx, mgr)
	Expect(err).ToNot(HaveOccurred())

	go func() {
		defer GinkgoRecover()
		Expect(mgr.Start(ctx)).To(Succeed(), "failed to run manager")
	}()
})

var _ = AfterSuite(func() {
	cancel()
	By("tearing down the test environment")
	Expect(testEnv.Stop()).To(Succeed())
})
