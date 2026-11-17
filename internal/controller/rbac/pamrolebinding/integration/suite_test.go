package integration

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	rbacv1alpha1 "github.com/gocardless/theatre/v5/api/rbac/v1alpha1"
	"github.com/gocardless/theatre/v5/internal/controller/rbac/pamrolebinding"
)

var (
	testEnv   *envtest.Environment
	k8sClient client.Client
	grants    *pamrolebinding.FakeGrantLister
	clock     *fakeClock
	ctx       context.Context
	cancel    context.CancelFunc
)

// fakeClock lets specs move time forward to expire grants.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func TestSuite(t *testing.T) {
	SetDefaultEventuallyTimeout(10 * time.Second)
	RegisterFailHandler(Fail)
	RunSpecs(t, "controllers/rbac/pamrolebinding/integration")
}

var _ = BeforeSuite(func() {
	logf.SetLogger(zap.New(zap.WriteTo(GinkgoWriter), zap.UseDevMode(true)))
	ctx, cancel = context.WithCancel(context.Background())

	testEnv = &envtest.Environment{
		CRDDirectoryPaths: []string{filepath.Join("..", "..", "..", "..", "..", "config", "crd", "bases")},
	}
	cfg, err := testEnv.Start()
	Expect(err).ToNot(HaveOccurred())

	scheme := runtime.NewScheme()
	Expect(clientgoscheme.AddToScheme(scheme)).To(Succeed())
	Expect(rbacv1alpha1.AddToScheme(scheme)).To(Succeed())

	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:  scheme,
		Metrics: metricsserver.Options{BindAddress: "0"},
	})
	Expect(err).ToNot(HaveOccurred())

	// Read straight from the API server, so specs don't race the manager's cache.
	k8sClient, err = client.New(cfg, client.Options{Scheme: scheme})
	Expect(err).ToNot(HaveOccurred())
	grants = pamrolebinding.NewFakeGrantLister()
	clock = &fakeClock{now: time.Now()}

	Expect((&pamrolebinding.Reconciler{
		Client:   mgr.GetClient(),
		Log:      ctrl.Log.WithName("controllers").WithName("PAMRoleBinding"),
		Scheme:   mgr.GetScheme(),
		Recorder: mgr.GetEventRecorderFor("rbac-manager"),
		Grants:   grants,
		// Short, so specs see PAM changes quickly.
		RefreshInterval: 200 * time.Millisecond,
		Now:             clock.Now,
	}).SetupWithManager(mgr)).To(Succeed())

	go func() {
		defer GinkgoRecover()
		Expect(mgr.Start(ctx)).To(Succeed())
	}()
})

var _ = AfterSuite(func() {
	cancel()
	Expect(testEnv.Stop()).To(Succeed())
})
