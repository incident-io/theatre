package main

import (
	"context"
	"fmt"
	"os"

	"cloud.google.com/go/compute/metadata"
	"github.com/alecthomas/kingpin"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	directoryv1 "google.golang.org/api/admin/directory/v1"
	"google.golang.org/api/impersonate"
	"google.golang.org/api/option"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp" // this is required to auth against GCP
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	rbacv1alpha1 "github.com/gocardless/theatre/v5/api/rbac/v1alpha1"
	"github.com/gocardless/theatre/v5/cmd"
	directoryrolebinding "github.com/gocardless/theatre/v5/internal/controller/rbac"
	"github.com/gocardless/theatre/v5/internal/controller/rbac/pamrolebinding"
	"github.com/gocardless/theatre/v5/pkg/signals"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")

	app = kingpin.New("rbac-manager", "Manages rbac.crd.gocardless.com resources").Version(cmd.VersionStanza())

	refresh    = app.Flag("refresh", "Refresh interval checking directory sources").Default("1m").Duration()
	commonOpts = cmd.NewCommonOptions(app).WithMetrics(app)

	// DirectoryRoleBinding needs update on every RoleBinding it owns. Clusters that don't use
	// it can turn it off, and then drop that permission from rbac-manager's ClusterRole.
	directoryRoleBindingEnabled = app.Flag("directory-role-binding", "Run the DirectoryRoleBinding controller").Default("true").Bool()

	// Uses Application Default Credentials, which need privilegedaccessmanager.grants.list
	// on the project rbac-manager runs in.
	pamEnabled = app.Flag("pam", "Run the PAMRoleBinding controller").Default("false").Bool()
	pamRefresh = app.Flag("pam-refresh", "How often each PAMRoleBinding is synced with PAM").Default("10s").Duration()

	// All GoogleGroup related settings
	googleEnabled  = app.Flag("google", "Enable GoogleGroup subject Kind").Default("false").Bool()
	googleSubject  = app.Flag("google-subject", "Service account subject").Default("robot-admin@gocardless.com").String()
	googleCacheTTL = app.Flag("google-refresh", "Cache TTL for Google directory operations").Default("5m").Duration()
)

func init() {
	_ = clientgoscheme.AddToScheme(scheme)
	_ = rbacv1alpha1.AddToScheme(scheme)

	// Register custom metrics with the global controller runtime prometheus registry
	metrics.Registry.MustRegister(cmd.BuildInfo)
}

func main() {
	kingpin.MustParse(app.Parse(os.Args[1:]))
	logger := commonOpts.Logger()

	ctx, cancel := signals.SetupSignalHandler()
	defer cancel()

	provider := directoryrolebinding.DirectoryProvider{}

	if *googleEnabled {
		googleDirectoryService, err := createGoogleDirectory(ctx, *googleSubject)
		if err != nil {
			app.Fatalf("failed to create Google Admin client: %v", err)
		}

		logger.Info(
			"registering provider",
			"event", "provider.register", "kind", rbacv1alpha1.GoogleGroupKind)
		provider.Register(
			rbacv1alpha1.GoogleGroupKind,
			directoryrolebinding.NewCachedDirectory(
				logger, directoryrolebinding.NewGoogleDirectory(googleDirectoryService.Members), *googleCacheTTL,
			),
		)
	}

	webhookServer := webhook.NewServer(webhook.Options{Port: 9443})

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: scheme,
		Metrics: metricsserver.Options{
			BindAddress: fmt.Sprintf("%s:%d", commonOpts.MetricAddress, commonOpts.MetricPort),
		},
		WebhookServer:                 webhookServer,
		LeaderElection:                commonOpts.ManagerLeaderElection,
		LeaderElectionID:              "rbac.crds.gocardless.com",
		LeaderElectionReleaseOnCancel: true,
	})
	if err != nil {
		app.Fatalf("failed to create manager: %v", err)
	}

	if *directoryRoleBindingEnabled {
		if err = (&directoryrolebinding.DirectoryRoleBindingReconciler{
			Client:          mgr.GetClient(),
			Ctx:             ctx,
			Log:             ctrl.Log.WithName("controllers").WithName("DirectoryRoleBinding"),
			Provider:        provider,
			RefreshInterval: *refresh,
			Scheme:          mgr.GetScheme(),
		}).SetupWithManager(mgr); err != nil {
			setupLog.Error(err, "unable to create controller", "controller", "DirectoryRoleBinding")
			os.Exit(1)
		}
	} else {
		logger.Info("DirectoryRoleBinding controller disabled", "event", "controller.disabled", "controller", "DirectoryRoleBinding")
	}

	if *pamEnabled {
		// Only honour entitlements in our own project: anyone who can create a PAMRoleBinding
		// could otherwise point it at an entitlement in a project they control. Refuse to
		// start rather than honour any project.
		projects, err := ownProject(ctx)
		if err != nil {
			app.Fatalf("failed to find this cluster's Google Cloud project, which PAMRoleBindings' entitlements must be in: %v", err)
		}
		logger.Info("PAMRoleBindings limited to this project's entitlements", "event", "pam.projects", "projects", projects)

		grants, err := pamrolebinding.NewPAMGrantLister(ctx)
		if err != nil {
			app.Fatalf("failed to create PAM client: %v", err)
		}
		defer grants.Close()

		if err = (&pamrolebinding.Reconciler{
			Client:              mgr.GetClient(),
			Log:                 ctrl.Log.WithName("controllers").WithName("PAMRoleBinding"),
			Scheme:              mgr.GetScheme(),
			Recorder:            mgr.GetEventRecorderFor("rbac-manager"),
			Grants:              grants,
			RefreshInterval:     *pamRefresh,
			EntitlementProjects: projects,
		}).SetupWithManager(ctx, mgr); err != nil {
			setupLog.Error(err, "unable to create controller", "controller", "PAMRoleBinding")
			os.Exit(1)
		}
	}

	if err := mgr.Start(ctx); err != nil {
		app.Fatalf("failed to run manager: %v", err)
	}
}

func createGoogleDirectory(ctx context.Context, subject string) (*directoryv1.Service, error) {
	scopes := []string{
		directoryv1.AdminDirectoryGroupMemberReadonlyScope,
		directoryv1.AdminDirectoryGroupReadonlyScope,
	}

	creds, err := google.FindDefaultCredentials(ctx, scopes...)
	if err != nil {
		return nil, err
	}

	var ts oauth2.TokenSource

	// If the found credential doesn't contain JSON, try to fallback to workload identity
	if len(creds.JSON) == 0 {
		// Get the email address associated with the service account. The account may be empty
		// or the string "default" to use the instance's main account.
		principal, err := metadata.Email("default")
		if err != nil {
			return nil, err
		}

		// Access to the directory API must be signed with a Subject to enable domain selection.
		config := impersonate.CredentialsConfig{
			TargetPrincipal: principal,
			Scopes:          scopes,
			Subject:         subject,
		}

		// Impersonation (as itself) is required as the federated access token obtained from the GCE
		// metadata server is not sufficient for acting as the subject via domain-wide delegation.
		// For delegation to work, we need to sign a JWT with the the "sub" claim set to subject -
		// this happens implicitly through impersonation.
		ts, err = impersonate.CredentialsTokenSource(ctx, config)
		if err != nil {
			return nil, err
		}
	} else {
		conf, err := google.JWTConfigFromJSON(creds.JSON, scopes...)
		if err != nil {
			return nil, err
		}

		// Access to the directory API must be signed with a Subject to enable domain selection.
		conf.Subject = subject

		ts = conf.TokenSource(ctx)
	}

	return directoryv1.NewService(ctx, option.WithTokenSource(ts))
}

// ownProject returns both the project ID and number, as entitlement names can use either.
func ownProject(ctx context.Context) ([]string, error) {
	id, err := metadata.ProjectIDWithContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("reading project ID: %w", err)
	}
	number, err := metadata.NumericProjectIDWithContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("reading project number: %w", err)
	}
	if id == "" || number == "" {
		return nil, fmt.Errorf("metadata server returned an empty project ID (%q) or number (%q)", id, number)
	}
	return []string{id, number}, nil
}
