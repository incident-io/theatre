package runner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"text/tabwriter"
	"time"

	"gomodules.xyz/jsonpatch/v3"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
	"k8s.io/kubectl/pkg/cmd/get"
	"k8s.io/kubectl/pkg/util/term"
	"sigs.k8s.io/controller-runtime/pkg/client"

	rbacv1alpha1 "github.com/gocardless/theatre/apis/rbac/v1alpha1"
	workloadsv1alpha1 "github.com/gocardless/theatre/apis/workloads/v1alpha1"
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

	// TODO: For now we assume that all consoles are interactive, i.e. we setup a TTY on
	// them when spawning them. This does not enforce a requirement to attach to the console
	// though.
	// Later on we may need to implement non-interactive consoles, for processes which
	// expect a TTY to not be present?
	// However with these types of consoles it will not be possible to send input to them
	// when reattaching, e.g. attempting to send a SIGINT to cancel the running process.
	// Interactive bool
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
	Namespace string
	Selector  string
	Timeout   time.Duration
	Reason    string
	Command   []string
	Attach    bool

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

	opt := Options{Cmd: opts.Command, Timeout: int(opts.Timeout.Seconds()), Reason: opts.Reason}
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
	if err == consolePendingAuthorisationError {
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

	pod, containerName, err := c.GetAttachablePod(csl)
	if err != nil {
		return fmt.Errorf("could not find pod to attach to: %w", err)
	}

	err = opts.Hook.AttachingToConsole(csl)
	if err != nil {
		return err
	}

	if err := NewAttacher(c.clientset, opts.KubeConfig).Attach(ctx, pod, containerName, opts.IO); err != nil {
		return fmt.Errorf("failed to attach to console: %w", err)
	}

	return nil
}

func NewAttacher(clientset kubernetes.Interface, restconfig *rest.Config) *Attacher {
	return &Attacher{clientset, restconfig}
}

// Attacher knows how to attach to stdio of an existing container, relaying io
// to the parent process file descriptors.
type Attacher struct {
	clientset  kubernetes.Interface
	restconfig *rest.Config
}

// Attach will interactively attach to a containers output, creating a new TTY
// and hooking this into the current processes file descriptors.
func (a *Attacher) Attach(ctx context.Context, pod *corev1.Pod, containerName string, streams IOStreams) error {
	req := a.clientset.CoreV1().RESTClient().Post().
		Resource("pods").
		Namespace(pod.GetNamespace()).
		Name(pod.GetName()).
		SubResource("attach")

	req.VersionedParams(
		&corev1.PodAttachOptions{
			Stdin:     true,
			Stdout:    true,
			Stderr:    true,
			TTY:       true,
			Container: containerName,
		},
		scheme.ParameterCodec,
	)

	remoteExecutor, err := remotecommand.NewSPDYExecutor(a.restconfig, "POST", req.URL())
	if err != nil {
		return fmt.Errorf("failed to create SPDY executor: %w", err)
	}

	streamOptions, safe := CreateInteractiveStreamOptions(streams)

	return safe(func() error { return remoteExecutor.Stream(streamOptions) })
}

// CreateInteractiveStreamOptions constructs streaming configuration that
// attaches the default OS stdout, stderr, stdin, with a tty, and an additional
// function which should be used to wrap any interactive process that will make
// use of the tty.
func CreateInteractiveStreamOptions(streams IOStreams) (remotecommand.StreamOptions, func(term.SafeFunc) error) {
	// TODO: We may want to setup a parent interrupt handler, so that if/when the
	// pod is terminated while a user is attached, they aren't left with their
	// terminal in a strange state, if they're running something curses-based in
	// the console.
	// Parent: ...
	tty := term.TTY{
		In:     streams.In,
		Out:    streams.ErrOut,
		Raw:    true,
		TryDev: false,
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

type AuthoriseOptions struct {
	Namespace   string
	ConsoleName string
	Username    string
}

func (c *Runner) Authorise(ctx context.Context, opts AuthoriseOptions) error {
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

	err = c.kubeClient.Patch(ctx, &authz, client.ConstantPatch(types.JSONPatchType, patchBytes))
	if err != nil {
		return err
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
		},
	}

	err := c.kubeClient.Create(
		context.TODO(),
		csl,
	)
	return csl, err
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
		identifiers := []string{}
		for _, item := range templates.Items {
			identifiers = append(identifiers, item.Namespace+"/"+item.Name)
		}

		return nil, fmt.Errorf(
			"expected to discover 1 console template, but actually found: %s",
			identifiers,
		)
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
	consolePendingAuthorisationError = errors.New("console pending authorisation")
	consoleStoppedError              = errors.New("console is stopped")
	consoleNotFoundError             = errors.New("console not found")
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
		return csl, consolePendingAuthorisationError
	}
	if isStopped(csl) {
		return nil, consoleStoppedError
	}

	status := w.ResultChan()
	defer w.Stop()

	for {
		select {
		case event, ok := <-status:
			// If our channel is closed, exit with error, as we'll otherwise assume
			// we were successful when we never reached this state.
			if !ok {
				return nil, errors.New("watch channel closed")
			}

			obj := event.Object.(*unstructured.Unstructured)
			runtime.DefaultUnstructuredConverter.FromUnstructured(obj.UnstructuredContent(), csl)

			if isRunning(csl) {
				return csl, nil
			}
			if isPendingAuthorisation(csl) {
				return csl, consolePendingAuthorisationError
			}
			if isStopped(csl) {
				return nil, consoleStoppedError
			}
		case <-ctx.Done():
			if csl == nil {
				return nil, fmt.Errorf("%s: %w", consoleNotFoundError, ctx.Err())
			}
			return nil, fmt.Errorf("console's last phase was: %v: %w", csl.Status.Phase, ctx.Err())
		}
	}
}

func (c *Runner) waitForRoleBinding(ctx context.Context, csl *workloadsv1alpha1.Console) error {
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
func (c *Runner) GetAttachablePod(csl *workloadsv1alpha1.Console) (*corev1.Pod, string, error) {
	pod := &corev1.Pod{}
	err := c.kubeClient.Get(context.TODO(), client.ObjectKey{Namespace: csl.Namespace, Name: csl.Status.PodName}, pod)
	if err != nil {
		return nil, "", err
	}

	for _, c := range pod.Spec.Containers {
		if c.TTY {
			return pod, c.Name, nil
		}
	}

	return nil, "", errors.New("no attachable pod found")
}
