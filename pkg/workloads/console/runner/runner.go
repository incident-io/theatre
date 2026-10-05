package runner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"reflect"
	"strings"
	"sync/atomic"
	"text/tabwriter"
	"time"

	"gomodules.xyz/jsonpatch/v3"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/fields"
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
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/remotecommand"
	watchtools "k8s.io/client-go/tools/watch"
	"k8s.io/kubectl/pkg/cmd/get"
	cmdutil "k8s.io/kubectl/pkg/cmd/util"
	"k8s.io/kubectl/pkg/scheme"
	"k8s.io/kubectl/pkg/util/term"
	"sigs.k8s.io/controller-runtime/pkg/client"

	rbacv1alpha1 "github.com/gocardless/theatre/v5/api/rbac/v1alpha1"
	workloadsv1alpha1 "github.com/gocardless/theatre/v5/api/workloads/v1alpha1"
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
	Labels  labels.Set
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

	// Allow specifying additional labels to be attached to the pod
	Labels map[string]string

	// Lifecycle hook to notify when the state of the console changes
	Hook LifecycleHook
}

// WithDefaults sets any unset options to defaults
func (opts CreateOptions) WithDefaults() CreateOptions {
	if opts.Hook == nil {
		opts.Hook = DefaultLifecycleHook{}
	}
	if opts.Labels == nil {
		opts.Labels = labels.Set{}
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

	opt := Options{
		Cmd:            opts.Command,
		Timeout:        int(opts.Timeout.Seconds()),
		Reason:         opts.Reason,
		Noninteractive: opts.Noninteractive,
		Labels:         labels.Merge(labels.Set{}, opts.Labels),
	}

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

// getListWatch is a convenience helper for creating a ListWatch for
// different object types.
//
// It is meant to be used in methods that wait for objects:
// - waitForSuccess (Pod)
// - waitForConsole (Console)
// - waitForRoleBinding (RoleBinding)
func getListWatch[T runtime.Object](ctx context.Context, client resourceInterface[T], fieldSelector string) *cache.ListWatch {
	return &cache.ListWatch{
		ListFunc: func(opts metav1.ListOptions) (runtime.Object, error) {
			opts.FieldSelector = fieldSelector
			return client.List(ctx, opts)
		},
		WatchFunc: func(opts metav1.ListOptions) (watch.Interface, error) {
			opts.FieldSelector = fieldSelector
			return client.Watch(ctx, opts)
		},
	}
}

// resourceInterface is a generic interface for use with getListWatch
type resourceInterface[T runtime.Object] interface {
	List(ctx context.Context, opts metav1.ListOptions) (T, error)
	Watch(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error)
}

// checkPodState returns (true, nil) when the pod has reached a terminal
// success state, (false, nil) to continue watching, or (true, err) on failure.
func checkPodState(pod *corev1.Pod) (bool, error) {
	switch pod.Status.Phase {
	case corev1.PodRunning:
		return false, nil
	case corev1.PodSucceeded:
		return true, nil
	default:
		return true, fmt.Errorf("pod in unexpected state %s: %s", pod.Status.Phase, pod.Status.Message)
	}
}

// checkAttachedContainerState is checkPodState for the container we attach to. Once that
// container has terminated the console is over, even if the pod's phase hasn't caught up
// yet, and its exit code decides the result.
func checkAttachedContainerState(pod *corev1.Pod, containerName string) (bool, error) {
	if terminated := terminatedState(pod, containerName); terminated != nil {
		return true, containerExitError(pod, containerName, terminated)
	}

	return checkPodState(pod)
}

// ContainerExitError is returned when the console's container exits with a non-zero code.
// It implements k8s.io/utils/exec.ExitError, so a CLI can exit with the same code, as
// kubectl does.
type ContainerExitError struct {
	Pod       string
	Container string
	ExitCode  int32
	Reason    string
}

func (e *ContainerExitError) Error() string {
	msg := fmt.Sprintf("console container %s in pod %s exited with code %d", e.Container, e.Pod, e.ExitCode)
	if e.Reason != "" {
		msg += " (" + e.Reason + ")"
	}

	return msg
}

func (e *ContainerExitError) ExitStatus() int {
	return int(e.ExitCode)
}

func (e *ContainerExitError) Exited() bool {
	return true
}

func (e *ContainerExitError) String() string {
	return e.Error()
}

func terminatedState(pod *corev1.Pod, containerName string) *corev1.ContainerStateTerminated {
	for _, status := range pod.Status.ContainerStatuses {
		if status.Name == containerName {
			return status.State.Terminated
		}
	}

	return nil
}

// containerExitError returns nil for a container that exited 0.
func containerExitError(pod *corev1.Pod, containerName string, terminated *corev1.ContainerStateTerminated) error {
	if terminated.ExitCode == 0 {
		return nil
	}

	return &ContainerExitError{
		Pod:       pod.Name,
		Container: containerName,
		ExitCode:  terminated.ExitCode,
		Reason:    terminated.Reason,
	}
}

func (c *Runner) waitForSuccess(ctx context.Context, csl *workloadsv1alpha1.Console) error {
	pod, containerName, err := c.GetAttachablePod(ctx, csl)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("retrieving pod: %w", err)
	}

	fieldSelector := fields.OneTermEqualSelector("metadata.name", pod.Name).String()
	namespacedPodClient := c.clientset.CoreV1().Pods(pod.Namespace)
	lw := getListWatch(ctx, namespacedPodClient, fieldSelector)

	// Precondition checks the current state from the informer's cache
	// before processing any watch events
	precondition := func(store cache.Store) (bool, error) {
		items := store.List()
		if len(items) == 0 {
			return true, nil // pod gone, treat as success
		}
		return checkAttachedContainerState(items[0].(*corev1.Pod), containerName)
	}

	// Condition processes each watch event
	condition := func(event watch.Event) (bool, error) {
		pod, ok := event.Object.(*corev1.Pod)
		if !ok {
			return false, fmt.Errorf("unexpected event object: %v", reflect.TypeOf(event.Object))
		}
		return checkAttachedContainerState(pod, containerName)
	}

	_, err = watchtools.UntilWithSync(ctx, lw, &corev1.Pod{}, precondition, condition)
	return err
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

	// A short command can finish before we get here. Attaching to it then only leaves
	// client-go's stdin copy writing to a closed stream once the user presses return, so
	// show what it printed instead.
	if terminated := terminatedState(pod, containerName); terminated != nil {
		_, _ = fmt.Fprintf(opts.IO.ErrOut, "Console has already finished, so showing its logs instead of attaching.\n")
		if err := c.copyLogs(ctx, pod, containerName, opts.IO); err != nil {
			_, _ = fmt.Fprintf(opts.IO.ErrOut, "WARN: failed to copy logs from pod: %v\n", err)
		}

		return containerExitError(pod, containerName, terminated)
	}

	err = opts.Hook.AttachingToConsole(csl)
	if err != nil {
		return err
	}

	attacher := newAttacher(c.clientset, opts.KubeConfig, !csl.Spec.Noninteractive)

	// client-go copies stdin to the container in a goroutine that outlives the attach,
	// blocked reading the terminal. Once the console is over, the gate turns whatever it
	// reads next into EOF, so that copy ends instead of writing to the closed stream.
	stdin := newStdinGate(opts.IO.In)
	defer stdin.Close()

	// The attacher can hang under some circumstances. Therefore we need to run it separately, and
	// not wait for its completion before exiting the CLI.
	attachErrCh := make(chan error, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				attachErrCh <- fmt.Errorf("panic in attach goroutine: %v", r)
			}
		}()

		attachErr := attacher.Attach(ctx, pod, containerName, opts.IO, stdin)
		stdin.Close()
		attachErrCh <- attachErr
	}()

	// *Block* until our pod has completed.
	// NOTE: This effectively precludes the detach escape sequence (C-p C-q) from working, but
	// that's already non-functional in recent k8s versions anyway.
	// At this point, we deliberately don't immediately check the error, because our handling of it
	// depends on other conditions.
	podStatusErr := c.waitForSuccess(ctx, csl)
	stdin.Close()

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

// stdinGate passes reads through to the user's stdin until it's closed. A read that
// completes after Close returns EOF and drops what it read: the console has gone, so
// there's nowhere to send it.
type stdinGate struct {
	in     io.Reader
	closed atomic.Bool
}

func newStdinGate(in io.Reader) *stdinGate {
	return &stdinGate{in: in}
}

func (g *stdinGate) Read(p []byte) (int, error) {
	if g.closed.Load() {
		return 0, io.EOF
	}

	n, err := g.in.Read(p)
	if g.closed.Load() {
		return 0, io.EOF
	}

	return n, err
}

func (g *stdinGate) Close() {
	g.closed.Store(true)
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
// stdin replaces streams.In as what's copied to the container, while the TTY still uses
// streams.In to detect and configure the terminal.
func (a *attacher) Attach(ctx context.Context, pod *corev1.Pod, containerName string, streams IOStreams, stdin io.Reader) error {
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
		if streams.In != nil {
			streamOptions.Stdin = stdin
		}
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
func createExecutor(url *url.URL, config *rest.Config) (remotecommand.Executor, error) {
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
	lbls := labels.Merge(opts.Labels, template.Labels)

	// There is no easy way to only invoke validation, so we convert the labels to
	// a selector instead and discard its output, which will force the validation
	// to happen
	_, err := lbls.AsValidatedSelector()
	if err != nil {
		return nil, err
	}

	csl := &workloadsv1alpha1.Console{
		ObjectMeta: metav1.ObjectMeta{
			// Let Kubernetes generate a unique name
			GenerateName: template.Name + "-",
			Labels:       lbls,
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

	err = c.kubeClient.Create(
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

var errConsolePendingAuthorisation = errors.New("console pending authorisation")

// checkConsoleState returns (true, nil) when the console has reached a terminal
// success state, (false, nil) to continue watching, or (true, err) on failure.
func checkConsoleState(csl *workloadsv1alpha1.Console, waitForAuthorisation bool) (bool, error) {
	switch csl.Status.Phase {
	case workloadsv1alpha1.ConsoleRunning:
		return true, nil
	case workloadsv1alpha1.ConsolePendingAuthorisation:
		if !waitForAuthorisation {
			return true, errConsolePendingAuthorisation
		}
		return false, nil
	// If the console has already stopped it may have already run to
	// completion, so let's return it
	case workloadsv1alpha1.ConsoleStopped:
		return true, nil
	default:
		return false, nil
	}
}

func (c *Runner) waitForConsole(ctx context.Context, createdCsl workloadsv1alpha1.Console, waitForAuthorisation bool) (*workloadsv1alpha1.Console, error) {
	fieldSelector := fields.OneTermEqualSelector("metadata.name", createdCsl.Name).String()
	namespacedCslClient := c.consoleClient.Namespace(createdCsl.Namespace)
	lw := getListWatch(ctx, namespacedCslClient, fieldSelector)

	var resultCsl *workloadsv1alpha1.Console

	// Precondition checks the current state from the informer's cache
	// before processing any watch events
	precondition := func(store cache.Store) (bool, error) {
		items := store.List()
		if len(items) == 0 {
			return false, nil // not found yet, wait for events
		}
		obj := items[0].(*unstructured.Unstructured)
		csl := &workloadsv1alpha1.Console{}
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(
			obj.UnstructuredContent(), csl,
		); err != nil {
			return false, err
		}
		done, err := checkConsoleState(csl, waitForAuthorisation)
		if done {
			resultCsl = csl
		}
		return done, err
	}

	// Condition processes each watch event
	condition := func(event watch.Event) (bool, error) {
		obj, ok := event.Object.(*unstructured.Unstructured)
		if !ok {
			return false, fmt.Errorf("unexpected event object: %v", reflect.TypeOf(event.Object))
		}
		csl := &workloadsv1alpha1.Console{}
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(
			obj.UnstructuredContent(), csl,
		); err != nil {
			return false, err
		}
		done, err := checkConsoleState(csl, waitForAuthorisation)
		if done {
			resultCsl = csl
		}
		return done, err
	}

	_, err := watchtools.UntilWithSync(ctx, lw, &unstructured.Unstructured{}, precondition, condition)
	return resultCsl, err
}

func (c *Runner) waitForRoleBinding(ctx context.Context, csl *workloadsv1alpha1.Console) error {
	if csl.Status.Phase == workloadsv1alpha1.ConsoleStopped {
		return nil
	}

	fieldSelector := fields.OneTermEqualSelector("metadata.name", csl.Name).String()
	namespacedRBClient := c.clientset.RbacV1().RoleBindings(csl.Namespace)
	lw := getListWatch(ctx, namespacedRBClient, fieldSelector)

	precondition := func(store cache.Store) (bool, error) {
		items := store.List()
		if len(items) == 0 {
			return false, nil
		}
		rb := items[0].(*rbacv1.RoleBinding)
		return rbHasSubject(rb, csl.Spec.User), nil
	}

	condition := func(event watch.Event) (bool, error) {
		rb, ok := event.Object.(*rbacv1.RoleBinding)
		if !ok {
			return false, fmt.Errorf("unexpected event object: %v", reflect.TypeOf(event.Object))
		}
		return rbHasSubject(rb, csl.Spec.User), nil
	}

	_, err := watchtools.UntilWithSync(ctx, lw, &rbacv1.RoleBinding{}, precondition, condition)
	return err
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
