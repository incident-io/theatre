package runner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"reflect"
	"strings"
	"text/tabwriter"
	"time"

	rbacv1alpha1 "github.com/gocardless/theatre/v4/apis/rbac/v1alpha1"
	workloadsv1alpha1 "github.com/gocardless/theatre/v4/apis/workloads/v1alpha1"
	"gomodules.xyz/jsonpatch/v3"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/httpstream"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
	"k8s.io/kubectl/pkg/cmd/get"
	cmdutil "k8s.io/kubectl/pkg/cmd/util"
	"k8s.io/kubectl/pkg/scheme"
	"k8s.io/kubectl/pkg/util/term"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Alias genericclioptions.IOStreams to avoid additional imports
type IOStreams genericclioptions.IOStreams

// Runner is responsible for managing the lifecycle of a console
type Runner struct {
	clientset     kubernetes.Interface
	consoleClient dynamic.NamespaceableResourceInterface
	kubeClient    client.Client
}

// Options defines the parameters that can be set upon a new console
type Options struct {
	Cmd     []string
	Timeout int
	Reason  string
	// Whether or not to enable a TTY for the console. Typically this
	// should be set to false but some execution environments, eg
	// Tekton, do not like attaching to TTY-enabled pods.
	Noninteractive bool
}

// New builds a runner
func New(cfg *rest.Config) (*Runner, error) {
	// create a client that can be used to attach to consoles pod
	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}

	// create a client that can be used to watch a console CRD
	dynClient, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	consoleClient := dynClient.Resource(workloadsv1alpha1.GroupVersion.WithResource("consoles"))

	// create a client that can be used for everything else
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = workloadsv1alpha1.AddToScheme(scheme)
	_ = rbacv1alpha1.AddToScheme(scheme)
	kubeClient, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		return nil, err
	}

	return &Runner{
		clientset:     clientset,
		consoleClient: consoleClient,
		kubeClient:    kubeClient,
	}, nil
}

// LifecycleHook provides a communication to react to console lifecycle changes
type LifecycleHook interface {
	AttachingToConsole(*workloadsv1alpha1.Console) error
	ConsoleCreated(*workloadsv1alpha1.Console) error
	ConsoleRequiresAuthorisation(*workloadsv1alpha1.Console, *workloadsv1alpha1.ConsoleAuthorisationRule) error
	ConsoleReady(*workloadsv1alpha1.Console) error
	TemplateFound(*workloadsv1alpha1.ConsoleTemplate) error
}

var _ LifecycleHook = DefaultLifecycleHook{}

type DefaultLifecycleHook struct {
	AttachingToPodFunc               func(*workloadsv1alpha1.Console) error
	ConsoleCreatedFunc               func(*workloadsv1alpha1.Console) error
	ConsoleRequiresAuthorisationFunc func(*workloadsv1alpha1.Console, *workloadsv1alpha1.ConsoleAuthorisationRule) error
	ConsoleReadyFunc                 func(*workloadsv1alpha1.Console) error
	TemplateFoundFunc                func(*workloadsv1alpha1.ConsoleTemplate) error
}

func (d DefaultLifecycleHook) AttachingToConsole(c *workloadsv1alpha1.Console) error {
	if d.AttachingToPodFunc != nil {
		return d.AttachingToPodFunc(c)
	}
	return nil
}

func (d DefaultLifecycleHook) ConsoleCreated(c *workloadsv1alpha1.Console) error {
	if d.ConsoleCreatedFunc != nil {
		return d.ConsoleCreatedFunc(c)
	}
	return nil
}

func (d DefaultLifecycleHook) ConsoleRequiresAuthorisation(c *workloadsv1alpha1.Console, r *workloadsv1alpha1.ConsoleAuthorisationRule) error {
	if d.ConsoleRequiresAuthorisationFunc != nil {
		return d.ConsoleRequiresAuthorisationFunc(c, r)
	}
	return nil
}

func (d DefaultLifecycleHook) ConsoleReady(c *workloadsv1alpha1.Console) error {
	if d.ConsoleReadyFunc != nil {
		return d.ConsoleReadyFunc(c)
	}
	return nil
}

func (d DefaultLifecycleHook) TemplateFound(c *workloadsv1alpha1.ConsoleTemplate) error {
	if d.TemplateFoundFunc != nil {
		return d.TemplateFoundFunc(c)
	}
	return nil
}

// CreateOptions encapsulates the arguments to create a console
type CreateOptions struct {
	Namespace      string
	Selector       string
	Timeout        time.Duration
	Reason         string
	Command        []string
	Attach         bool
	Noninteractive bool

	// Options only used when Attach is true
	KubeConfig *rest.Config
	IO         IOStreams

	// Lifecycle hook to notify when the state of the console changes
	Hook LifecycleHook
}

// WithDefaults sets any unset options to defaults
func (opts CreateOptions) WithDefaults() CreateOptions {
	if opts.Hook == nil {
		opts.Hook = DefaultLifecycleHook{}
	}

	return opts
}

// Create attempts to create a console in the given in the given namespace after finding the a template using selectors.
func (c *Runner) Create(ctx context.Context, opts CreateOptions) (*workloadsv1alpha1.Console, error) {
	// Get options with any unset values defaulted
	opts = opts.WithDefaults()

	// Create and attach to the console
	tpl, err := c.FindTemplateBySelector(opts.Namespace, opts.Selector)
	if err != nil {
		return nil, err
	}

	err = opts.Hook.TemplateFound(tpl)
	if err != nil {
		return nil, err
	}

	opt := Options{Cmd: opts.Command, Timeout: int(opts.Timeout.Seconds()), Reason: opts.Reason, Noninteractive: opts.Noninteractive}
	csl, err := c.CreateResource(tpl.Namespace, *tpl, opt)
	if err != nil {
		return nil, err
	}

	err = opts.Hook.ConsoleCreated(csl)
	if err != nil {
		return csl, err
	}

	// Wait for authorisation step or until ready
	_, err = c.WaitUntilReady(ctx, *csl, false)
	if err == errConsolePendingAuthorisation {
		rule, err := tpl.GetAuthorisationRuleForCommand(opts.Command)
		if err != nil {
			return csl, fmt.Errorf("failed to get authorisation rule %w", err)
		}
		opts.Hook.ConsoleRequiresAuthorisation(csl, &rule)
	} else if err != nil {
		return nil, err
	}

	// Wait for the console to enter a ready state
	csl, err = c.WaitUntilReady(ctx, *csl, true)
	if err != nil {
		return nil, err
	}

	err = opts.Hook.ConsoleReady(csl)
	if err != nil {
		return csl, err
	}

	if opts.Attach {
		return csl, c.Attach(
			ctx,
			AttachOptions{
				Namespace:  csl.GetNamespace(),
				KubeConfig: opts.KubeConfig,
				Name:       csl.GetName(),
				IO:         opts.IO,
				Hook:       opts.Hook,
			},
		)
	}

	return csl, nil
}

func (c *Runner) waitForPodCompletion(ctx context.Context, csl *workloadsv1alpha1.Console) error {
	isRunning := func(pod *corev1.Pod) bool {
		return pod != nil && pod.Status.Phase == corev1.PodRunning
	}

	succeeded := func(pod *corev1.Pod) bool {
		return pod != nil && pod.Status.Phase == corev1.PodSucceeded
	}

	pod, _, err := c.GetAttachablePod(ctx, csl)
	if err != nil {
		return err
	}

	listOptions := metav1.SingleObject(pod.ObjectMeta)

	// Handle an expired watch up to 3 times
	// This loop only interates on an expired watch, all other code paths return from this function
	maxAttempts := 3
	for i := 0; i < maxAttempts; i++ {
		w, err := c.clientset.CoreV1().Pods(pod.Namespace).Watch(ctx, listOptions)
		if err != nil {
			return fmt.Errorf("error watching pod: %w", err)
		}

		// We need to fetch the pod again now we have a watcher to avoid a race
		// where the pod completed before we were listening for watch events
		pod, _, err = c.GetAttachablePod(ctx, csl)
		if err != nil {
			// If we can't find the pod, then we should assume it finished successfully. Otherwise
			// we might race against the operator to access a pod it wants to delete, and cause
			// our runner to exit with error when all is fine.
			//
			// TODO: It may be better to recheck the console and look in its status?
			if apierrors.IsNotFound(err) {
				fmt.Fprintf(os.Stderr, "WARN: pod no longer exists, assuming success")
				return nil
			}

			return fmt.Errorf("error retrieving pod: %w", err)
		}

		if succeeded(pod) {
			return nil
		}

		if !isRunning(pod) {
			return podFailedError(pod)
		}

		status := w.ResultChan()
		defer w.Stop()

		// If we get a watch expired error, we jump to this label, which will jump to the sleep after the for loop
	WATCHEXPIRED:
		for {
			select {
			case event, ok := <-status:
				// If our channel is closed, exit with error, as we'll otherwise assume
				// we were successful when we never reached this state.
				if !ok {
					return errors.New("pod watch channel closed")
				}

				// We can receive *metav1.Status events in the situation where there's an error, in
				// which case we should exit early, unless it is a watch expired error, in which case we try again.
				if status, ok := event.Object.(*metav1.Status); ok {
					if status.Reason == metav1.StatusReasonExpired {
						// Recreating a watch from the previous ResourceVersion is not guaranteed to work, and can just return another expired watch.
						// Setting the ResourceVersion to an empty string will cause the watch to start from the start of that pod's history, which should avoid the issue.
						listOptions.ResourceVersion = ""
						break WATCHEXPIRED
					}
					return fmt.Errorf("received failure from Kubernetes: %s: %s", status.Reason, status.Message)
				}

				// We should be safe now, as a watcher should return either Status or the type we
				// asked it for. But we've been wrong before, and it wasn't easy to figure out what
				// happened when we didn't print the type of the event.
				pod, ok := event.Object.(*corev1.Pod)
				if !ok {
					return fmt.Errorf("received an event that didn't reference a pod, which is unexpected: %v",
						reflect.TypeOf(event.Object))
				}

				if succeeded(pod) {
					return nil
				}
				if !isRunning(pod) {
					return podFailedError(pod)
				}
			case <-ctx.Done():
				return fmt.Errorf("pod's last phase was: %v: %w", pod.Status.Phase, ctx.Err())
			}
		}
	}
	// This error will only be raised after we have used all attempts to get a successful watch for the pod
	return fmt.Errorf("received watch expired %d times", maxAttempts)
}

type GetOptions struct {
	Namespace   string
	ConsoleName string
}

// Get provides a standardised method to get a console
func (c *Runner) Get(ctx context.Context, opts GetOptions) (*workloadsv1alpha1.Console, error) {
	var csl workloadsv1alpha1.Console
	err := c.kubeClient.Get(
		ctx,
		client.ObjectKey{
			Name:      opts.ConsoleName,
			Namespace: opts.Namespace,
		},
		&csl,
	)
	if err != nil {
		return nil, err
	}

	return &csl, nil
}

// AttachOptions encapsulates the arguments to attach to a console
type AttachOptions struct {
	Namespace  string
	KubeConfig *rest.Config
	Name       string

	IO IOStreams

	// Lifecycle hook to notify when the state of the console changes
	Hook LifecycleHook
}

// WithDefaults sets any unset options to defaults
func (opts AttachOptions) WithDefaults() AttachOptions {
	if opts.Hook == nil {
		opts.Hook = DefaultLifecycleHook{}
	}

	return opts
}

// Attach provides the ability to attach to a running console, given the console name
func (c *Runner) Attach(ctx context.Context, opts AttachOptions) error {
	// Get options with any unset values defaulted
	opts = opts.WithDefaults()

	csl, err := c.FindConsoleByName(opts.Namespace, opts.Name)
	if err != nil {
		return err
	}

	pod, containerName, err := c.GetAttachablePod(ctx, csl)
	if err != nil {
		return fmt.Errorf("could not find pod to attach to: %w", err)
	}

	err = opts.Hook.AttachingToConsole(csl)
	if err != nil {
		return err
	}

	attacher := newAttacher(c.clientset, opts.KubeConfig, !csl.Spec.Noninteractive)

	// The attacher can hang under some circumstances. Therefore we need to run it separately, and
	// not wait for its completion before exiting the CLI.
	attachErrCh := make(chan error, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				attachErrCh <- fmt.Errorf("panic in attach goroutine: %v", r)
			}
		}()

		attachErr := attacher.Attach(ctx, pod, containerName, opts.IO)
		attachErrCh <- attachErr
	}()

	// *Block* until our pod has completed.
	// NOTE: This effectively precludes the detach escape sequence (C-p C-q) from working, but
	// that's already non-functional in recent k8s versions anyway.
	// At this point, we deliberately don't immediately check the error, because our handling of it
	// depends on other conditions.
	podStatusErr := c.waitForPodCompletion(ctx, csl)

	// Our pod has now completed, and we have its exit status, so we wait for either of:
	// 1. The attach goroutine to complete.
	// 2. The attach goroutine to have *not* completed, after 5 seconds.
	select {
	case err := <-attachErrCh:
		// Our attach completed, either normally or with an error.
		if err != nil {
			if !strings.Contains(err.Error(), fmt.Sprintf("container %s not found in pod %s", containerName, pod.Name)) {
				fmt.Fprintf(opts.IO.ErrOut, "WARN: attach resulted in an error: %v\n", err)
				// It's quite a normal case that true, the pod has already terminated, quicker than
				// we could attach to it.
				// However, in this block, that *isn't* the case. We may have already copied some of
				// the console's output to the terminal, but we can't be sure of how much of it came
				// through, as we have no indicator of when the attach failed in respect to the
				// console pod's lifetime.
				// By re-dumping the logs, after this block, we can ensure that the user sees the
				// full output, but it could be duplicates of previously-dumped lines!
				fmt.Fprintf(opts.IO.ErrOut, "WARN: re-copying pod logs, duplicate output is possible\n")
			}

			if copyErr := c.copyLogs(ctx, pod, containerName, opts.IO); copyErr != nil {
				fmt.Fprintf(opts.IO.ErrOut, "WARN: failed to copy logs from pod: %v\n", copyErr)
			}
		}

		return podStatusErr

	case <-time.After(5 * time.Second):
		// Our attach didn't complete (maybe it's hanging), so we should continue so as not
		// to block program termination, especially in the case of a non-interactive
		// console.
		fmt.Fprintf(opts.IO.ErrOut, "WARN: attach didn't complete. re-copying pod logs, duplicate output is possible\n")

		if err := c.copyLogs(ctx, pod, containerName, opts.IO); err != nil {
			fmt.Fprintf(opts.IO.ErrOut, "WARN: failed to copy logs from pod: %v\n", err)
		}

		return podStatusErr
	}
}

func podFailedError(pod *corev1.Pod) error {
	reason := string(pod.Status.Phase)
	if pod.Status.Message != "" {
		reason = reason + ": " + pod.Status.Message
	}
	return fmt.Errorf("pod in unsuccessful state: %s", reason)
}

func (c *Runner) copyLogs(ctx context.Context, pod *corev1.Pod, containerName string, streams IOStreams) error {
	pods := c.clientset.CoreV1().Pods(pod.Namespace)

	logs, err := pods.GetLogs(pod.Name, &corev1.PodLogOptions{Container: containerName}).Stream(ctx)
	if err != nil {
		return err
	}

	defer logs.Close()

	_, err = io.Copy(streams.Out, logs)
	if err != nil {
		return err
	}
	return nil
}

func newAttacher(clientset kubernetes.Interface, restconfig *rest.Config, isInteractive bool) *attacher {
	return &attacher{clientset, restconfig, isInteractive}
}

// attacher knows how to attach to stdio of an existing container, relaying io
// to the parent process file descriptors, and optionally opening a TTY session.
type attacher struct {
	clientset     kubernetes.Interface
	restconfig    *rest.Config
	isInteractive bool
}

// Attach will attach to a container's output, and hooking into the current processes file descriptors.
// If we're in interactive mode, it'll do some extra setup around STDIN and TTYs.
// The function will block until the container terminates, or we encounter an error in our
// stream.
// NOTE: This will attach from the current point in the pod's output stream. In Kubernetes, there's
// still no way to use the Attach API in a way that retrieves previous terminal output, as per issue
// #27264.
// TODO: We could consider augmenting this with a call to retrieve logs, immediately before
// attaching.
func (a *attacher) Attach(ctx context.Context, pod *corev1.Pod, containerName string, streams IOStreams) error {
	req := a.clientset.CoreV1().RESTClient().Post().
		Resource("pods").
		Namespace(pod.GetNamespace()).
		Name(pod.GetName()).
		SubResource("attach")

	req.VersionedParams(
		&corev1.PodAttachOptions{
			Stdin:     a.isInteractive,
			Stdout:    true,
			Stderr:    true,
			TTY:       a.isInteractive,
			Container: containerName,
		},
		scheme.ParameterCodec,
	)

	remoteExecutor, err := createExecutor(req.URL(), a.restconfig)
	if err != nil {
		return fmt.Errorf("failed to create executor: %w", err)
	}

	// Set up our standard, non-interactive streaming.
	streamOptions := remotecommand.StreamOptions{
		Stderr: streams.ErrOut,
		Stdout: streams.Out,
		Stdin:  nil,
		Tty:    false,
	}
	safe := func(f term.SafeFunc) error { return f() }

	if a.isInteractive {
		streamOptions, safe = CreateInteractiveStreamOptions(streams)
	}

	return safe(func() error { return remoteExecutor.StreamWithContext(ctx, streamOptions) })
}

// CreateInteractiveStreamOptions constructs streaming configuration that
// attaches the default OS stdout, stderr, stdin, with a tty, and an additional
// function which should be used to wrap any interactive process that will make
// use of the tty.
func CreateInteractiveStreamOptions(streams IOStreams) (remotecommand.StreamOptions, func(term.SafeFunc) error) {
	tty := term.TTY{
		In:     streams.In,
		Out:    streams.ErrOut,
		Raw:    true,
		TryDev: false,

		// TODO: We may want to setup a parent interrupt handler, so that if/when the
		// pod is terminated while a user is attached, they aren't left with their
		// terminal in a strange state, if they're running something curses-based in
		// the console.
		// Parent: interrupt.Handler{...}
	}

	// This call spawns a goroutine to monitor/update the terminal size
	sizeQueue := tty.MonitorSize(tty.GetSize())

	return remotecommand.StreamOptions{
		Stderr:            streams.ErrOut,
		Stdout:            streams.Out,
		Stdin:             streams.In,
		Tty:               true,
		TerminalSizeQueue: sizeQueue,
	}, tty.Safe
}

// createExecutor returns the Executor or an error if one occurred.
// NOTE: Borrowed from `kubectl attach`.
func createExecutor(url *url.URL, config *restclient.Config) (remotecommand.Executor, error) {
	exec, err := remotecommand.NewSPDYExecutor(config, "POST", url)
	if err != nil {
		return nil, err
	}

	// Try to use the new websocket protocol, and the fallback executor is default, unless feature flag is explicitly disabled.
	if !cmdutil.RemoteCommandWebsockets.IsDisabled() {
		// WebSocketExecutor must be "GET" method as described in RFC 6455 Sec. 4.1 (page 17).
		websocketExec, err := remotecommand.NewWebSocketExecutor(config, "GET", url.String())
		if err != nil {
			return nil, err
		}
		exec, err = remotecommand.NewFallbackExecutor(websocketExec, exec, func(err error) bool {
			return httpstream.IsUpgradeFailure(err) || httpstream.IsHTTPSProxyError(err)
		})
		if err != nil {
			return nil, err
		}
	}
	return exec, nil
}

type AuthoriseOptions struct {
	Namespace   string
	ConsoleName string
	Username    string
	Attach      bool

	// Options only used when Attach is true
	KubeConfig *rest.Config
	IO         IOStreams

	// Lifecycle hook to notify when the state of the console changes
	Hook LifecycleHook
}

// WithDefaults sets any unset options to defaults
func (opts AuthoriseOptions) WithDefaults() AuthoriseOptions {
	if opts.Hook == nil {
		opts.Hook = DefaultLifecycleHook{}
	}

	return opts
}

func (c *Runner) Authorise(ctx context.Context, opts AuthoriseOptions) error {

	// Get options with any unset values defaulted
	opts = opts.WithDefaults()

	patch := []jsonpatch.Operation{
		jsonpatch.NewOperation(
			"add",
			"/spec/authorisations/-",
			rbacv1.Subject{
				Kind:      rbacv1.UserKind,
				Namespace: opts.Namespace,
				Name:      opts.Username,
			},
		),
	}

	patchBytes, err := json.Marshal(patch)
	if err != nil {
		return err
	}

	var authz workloadsv1alpha1.ConsoleAuthorisation
	err = c.kubeClient.Get(
		ctx,
		client.ObjectKey{
			Name:      opts.ConsoleName,
			Namespace: opts.Namespace,
		},
		&authz,
	)
	if err != nil {
		return err
	}

	err = c.kubeClient.Patch(ctx, &authz, client.RawPatch(types.JSONPatchType, patchBytes))
	if err != nil {
		return err
	}

	if opts.Attach {
		// Wait for the console to enter a ready state
		csl, err := c.Get(ctx, GetOptions{
			Namespace:   opts.Namespace,
			ConsoleName: opts.ConsoleName,
		})
		if err != nil {
			return err
		}
		_, err = c.WaitUntilReady(ctx, *csl, true)
		if err != nil {
			return err
		}
		err = opts.Hook.ConsoleReady(csl)
		if err != nil {
			return err
		}
		return c.Attach(
			ctx,
			AttachOptions{
				Namespace:  opts.Namespace,
				KubeConfig: opts.KubeConfig,
				Name:       opts.ConsoleName,
				IO:         opts.IO,
				Hook:       opts.Hook,
			},
		)
	}

	return nil
}

type ListOptions struct {
	Namespace string
	Username  string
	Selector  string
	Output    io.Writer
}

// List is a wrapper around ListConsolesByLabelsAndUser that will output to a specified output.
// This functionality is intended to be used in a CLI setting, where you are usually outputting to os.Stdout.
func (c *Runner) List(ctx context.Context, opts ListOptions) (ConsoleSlice, error) {
	consoles, err := c.ListConsolesByLabelsAndUser(opts.Namespace, opts.Username, opts.Selector)
	if err != nil {
		return nil, err
	}

	return consoles, consoles.Print(opts.Output)
}

// CreateResource builds a console according to the supplied options and submits it to the API
func (c *Runner) CreateResource(namespace string, template workloadsv1alpha1.ConsoleTemplate, opts Options) (*workloadsv1alpha1.Console, error) {
	csl := &workloadsv1alpha1.Console{
		ObjectMeta: metav1.ObjectMeta{
			// Let Kubernetes generate a unique name
			GenerateName: template.Name + "-",
			Labels:       labels.Merge(labels.Set{}, template.Labels),
			Namespace:    namespace,
		},
		Spec: workloadsv1alpha1.ConsoleSpec{
			ConsoleTemplateRef: corev1.LocalObjectReference{Name: template.Name},
			// If the flag is not provided then the value will default to 0. The controller
			// should detect this and apply the default timeout that is defined in the template.
			TimeoutSeconds: opts.Timeout,
			Command:        opts.Cmd,
			Reason:         opts.Reason,
			Noninteractive: opts.Noninteractive,
		},
	}

	err := c.kubeClient.Create(
		context.TODO(),
		csl,
	)
	return csl, err
}

// MultipleConsoleTemplateError is returned whenever our selector was too broad, and
// matched more than one ConsoleTemplate resource.
type MultipleConsoleTemplateError struct {
	ConsoleTemplates []workloadsv1alpha1.ConsoleTemplate
}

func (e MultipleConsoleTemplateError) Error() string {
	identifiers := []string{}
	for _, item := range e.ConsoleTemplates {
		identifiers = append(identifiers, item.Namespace+"/"+item.Name)
	}

	return fmt.Sprintf(
		"expected to discover 1 console template, but actually found: %s",
		identifiers,
	)
}

// FindTemplateBySelector will search for a template matching the given label
// selector and return errors if none or multiple are found (when the selector
// is too broad)
func (c *Runner) FindTemplateBySelector(namespace string, labelSelector string) (*workloadsv1alpha1.ConsoleTemplate, error) {
	var templates workloadsv1alpha1.ConsoleTemplateList
	selectorSet, err := labels.ConvertSelectorToLabelsMap(labelSelector)
	if err != nil {
		return nil, fmt.Errorf("invalid selector: %w", err)
	}

	opts := &client.ListOptions{Namespace: namespace, LabelSelector: labels.SelectorFromSet(selectorSet)}
	err = c.kubeClient.List(context.TODO(), &templates, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to list consoles templates: %w", err)
	}

	if len(templates.Items) != 1 {
		return nil, MultipleConsoleTemplateError{templates.Items}
	}

	template := templates.Items[0]

	return &template, nil
}

func (c *Runner) FindConsoleByName(namespace, name string) (*workloadsv1alpha1.Console, error) {
	// We must List then filter the slice instead of calling Get(name), otherwise
	// the real Kubernetes client will return the following error when namespace
	// is empty: "an empty namespace may not be set when a resource name is
	// provided".
	// The fake clientset generated by client-gen will not replicate this error in
	// unit tests.
	var allConsolesInNamespace workloadsv1alpha1.ConsoleList
	err := c.kubeClient.List(context.TODO(), &allConsolesInNamespace, &client.ListOptions{Namespace: namespace})
	if err != nil {
		return nil, err
	}

	var matchingConsoles []workloadsv1alpha1.Console
	for _, console := range allConsolesInNamespace.Items {
		if console.Name == name {
			matchingConsoles = append(matchingConsoles, console)
		}
	}

	if len(matchingConsoles) == 0 {
		return nil, fmt.Errorf("no consoles found with name: %s", name)
	}
	if len(matchingConsoles) > 1 {
		return nil, fmt.Errorf("too many consoles found with name: %s, please specify namespace", name)
	}

	return &matchingConsoles[0], nil
}

type ConsoleSlice []workloadsv1alpha1.Console

func (cs ConsoleSlice) Print(output io.Writer) error {
	w := tabwriter.NewWriter(output, 0, 8, 2, ' ', 0)

	if len(cs) == 0 {
		return nil
	}

	decoder := scheme.Codecs.UniversalDecoder(scheme.Scheme.PrioritizedVersionsAllGroups()...)

	printer, err := get.NewCustomColumnsPrinterFromSpec(
		"NAME:.metadata.name,NAMESPACE:.metadata.namespace,PHASE:.status.phase,CREATED:.metadata.creationTimestamp,USER:.spec.user,REASON:.spec.reason",
		decoder,
		false, // false => print headers
	)
	if err != nil {
		return err
	}

	for _, cnsl := range cs {
		printer.PrintObj(&cnsl, w)
	}

	// Flush the printed buffer to output
	w.Flush()

	return nil
}

func (c *Runner) ListConsolesByLabelsAndUser(namespace, username, labelSelector string) (ConsoleSlice, error) {
	// We cannot use a FieldSelector on spec.user in conjunction with the
	// LabelSelector for CRD types like Console. The error message "field label
	// not supported: spec.user" is returned by the real Kubernetes client.
	// See https://github.com/kubernetes/kubernetes/issues/53459.
	var csls workloadsv1alpha1.ConsoleList
	selectorSet, err := labels.ConvertSelectorToLabelsMap(labelSelector)
	if err != nil {
		return nil, fmt.Errorf("invalid selector: %w", err)
	}

	opts := &client.ListOptions{Namespace: namespace, LabelSelector: labels.SelectorFromSet(selectorSet)}
	err = c.kubeClient.List(context.TODO(), &csls, opts)

	var filtered []workloadsv1alpha1.Console
	for _, csl := range csls.Items {
		if username == "" || csl.Spec.User == username {
			filtered = append(filtered, csl)
		}
	}
	return filtered, err
}

// WaitUntilReady will block until the console reaches a phase that indicates
// that it's ready to be attached to, or has failed.
// It will then block until an associated RoleBinding exists that contains the
// console user in its subject list. This RoleBinding gives the console user
// permission to attach to the pod.
func (c *Runner) WaitUntilReady(ctx context.Context, createdCsl workloadsv1alpha1.Console, waitForAuthorisation bool) (*workloadsv1alpha1.Console, error) {
	csl, err := c.waitForConsole(ctx, createdCsl, waitForAuthorisation)
	if err != nil {
		return nil, err
	}

	if err := c.waitForRoleBinding(ctx, csl); err != nil {
		return nil, err
	}

	return csl, nil
}

var (
	errConsoleNotFound             = errors.New("console not found")
	errConsolePendingAuthorisation = errors.New("console pending authorisation")
)

func (c *Runner) waitForConsole(ctx context.Context, createdCsl workloadsv1alpha1.Console, waitForAuthorisation bool) (*workloadsv1alpha1.Console, error) {
	isRunning := func(csl *workloadsv1alpha1.Console) bool {
		return csl != nil && csl.Status.Phase == workloadsv1alpha1.ConsoleRunning
	}
	isPendingAuthorisation := func(csl *workloadsv1alpha1.Console) bool {
		return !waitForAuthorisation &&
			csl != nil &&
			csl.Status.Phase == workloadsv1alpha1.ConsolePendingAuthorisation
	}
	isStopped := func(csl *workloadsv1alpha1.Console) bool {
		return csl != nil && csl.Status.Phase == workloadsv1alpha1.ConsoleStopped
	}

	listOptions := metav1.SingleObject(createdCsl.ObjectMeta)
	w, err := c.consoleClient.Namespace(createdCsl.Namespace).Watch(ctx, listOptions)
	if err != nil {
		return nil, fmt.Errorf("error watching console: %w", err)
	}

	// Get the console, because watch will only give us an event when something
	// is changed, and the phase could have already stabilised before the watch
	// is set up.
	csl := &workloadsv1alpha1.Console{}

	err = c.kubeClient.Get(ctx, client.ObjectKey{Name: createdCsl.Name, Namespace: createdCsl.Namespace}, csl)
	if err != nil && !apierrors.IsNotFound(err) {
		return nil, fmt.Errorf("error retrieving console: %w", err)
	}

	// If the console is already running then there's nothing to do
	if isRunning(csl) {
		return csl, nil
	}
	if isPendingAuthorisation(csl) {
		return csl, errConsolePendingAuthorisation
	}
	// If the console has already stopped it may have already run to
	// completion, so let's return it
	if isStopped(csl) {
		return csl, nil
	}

	status := w.ResultChan()
	defer w.Stop()

	for {
		select {
		case event, ok := <-status:
			// If our channel is closed, exit with error, as we'll otherwise assume
			// we were successful when we never reached this state.
			if !ok {
				return nil, errors.New("console watch channel closed")
			}

			// We can ignore Bookmark events, because we aren't making requests using bookmarks.
			//
			// If we encounter an Error event, then igore this too.
			// We'll instead wait until the channel is closed, or our context timeout is
			// reached.
			if event.Type == watch.Bookmark || event.Type == watch.Error {
				continue
			}

			obj, ok := event.Object.(*unstructured.Unstructured)
			if !ok {
				return nil, fmt.Errorf("failed to cast watch event")
			}

			err = runtime.DefaultUnstructuredConverter.FromUnstructured(obj.UnstructuredContent(), csl)
			if err != nil {
				return nil, fmt.Errorf("error converting console object: %w", err)
			}

			if isRunning(csl) {
				return csl, nil
			}
			if isPendingAuthorisation(csl) {
				return csl, errConsolePendingAuthorisation
			}
			// If the console has already stopped it may have already run to
			// completion, so let's return it
			if isStopped(csl) {
				return csl, nil
			}
		case <-ctx.Done():
			if csl == nil {
				return nil, fmt.Errorf("%s: %w", errConsoleNotFound, ctx.Err())
			}
			return nil, fmt.Errorf("console's last phase was: %v: %w", csl.Status.Phase, ctx.Err())
		}
	}
}

func (c *Runner) waitForRoleBinding(ctx context.Context, csl *workloadsv1alpha1.Console) error {
	if csl.Status.Phase == workloadsv1alpha1.ConsoleStopped {
		return nil
	}

	rbClient := c.clientset.RbacV1().RoleBindings(csl.Namespace)
	watcher, err := rbClient.Watch(context.TODO(), metav1.ListOptions{FieldSelector: "metadata.name=" + csl.Name})
	if err != nil {
		return fmt.Errorf("error watching rolebindings: %w", err)
	}
	defer watcher.Stop()

	// The Console controller might have already created a DirectoryRoleBinding
	// and the DirectoryRoleBinding controller might have created the RoleBinding
	// and updated its subject list by this point. If so, we are already done, and
	// might never receive another event from our RoleBinding Watcher, causing the
	// subsequent loop would block forever.
	// If the associated RoleBinding exists and has the console user in its
	// subject list, return early.
	rb, err := rbClient.Get(context.TODO(), csl.Name, metav1.GetOptions{})
	if err == nil && rbHasSubject(rb, csl.Spec.User) {
		return nil
	}

	rbEvents := watcher.ResultChan()
	for {
		select {
		case rbEvent, ok := <-rbEvents:
			if !ok {
				return errors.New("rolebinding event watcher channel closed")
			}

			rb := rbEvent.Object.(*rbacv1.RoleBinding)
			if rbHasSubject(rb, csl.Spec.User) {
				return nil
			}

			continue

		case <-ctx.Done():
			return fmt.Errorf("waiting for rolebinding interrupted: %w", ctx.Err())
		}
	}
}

func rbHasSubject(rb *rbacv1.RoleBinding, subjectName string) bool {
	for _, subject := range rb.Subjects {
		if subject.Name == subjectName {
			return true
		}
	}
	return false
}

// GetAttachablePod returns an attachable pod for the given console
func (c *Runner) GetAttachablePod(ctx context.Context, csl *workloadsv1alpha1.Console) (*corev1.Pod, string, error) {
	pod := &corev1.Pod{}
	err := c.kubeClient.Get(ctx, client.ObjectKey{Namespace: csl.Namespace, Name: csl.Status.PodName}, pod)
	if err != nil {
		return nil, "", err
	}

	containers := pod.Spec.Containers
	if len(containers) == 0 {
		return nil, "", errors.New("no attachable pod found")
	}

	if csl.Spec.Noninteractive {
		return pod, containers[0].Name, nil
	}

	for _, c := range containers {
		if c.TTY {
			return pod, c.Name, nil
		}
	}

	return nil, "", errors.New("no attachable pod found")
}
