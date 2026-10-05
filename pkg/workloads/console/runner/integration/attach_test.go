package integration

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	workloadsv1alpha1 "github.com/gocardless/theatre/v5/api/workloads/v1alpha1"
	"github.com/gocardless/theatre/v5/pkg/workloads/console/runner"
)

// syncBuffer is a bytes.Buffer that Attach's goroutines and the test can share.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

var _ = Describe("Attach", func() {
	var (
		consoleRunner *runner.Runner
		namespace     corev1.Namespace
		csl           workloadsv1alpha1.Console
		pod           corev1.Pod
		stdin         *io.PipeReader
		stdinWriter   *io.PipeWriter
		stdout        *syncBuffer
		stderr        *syncBuffer
		attaching     chan struct{}
	)

	BeforeEach(func() {
		var err error
		consoleRunner, err = runner.New(cfg)
		Expect(err).NotTo(HaveOccurred())

		namespace = newNamespace("")
		mustCreateNamespace(&namespace)

		pod = corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: namespace.Name, Name: "console-pod"},
			Spec: corev1.PodSpec{
				RestartPolicy: corev1.RestartPolicyNever,
				Containers: []corev1.Container{
					{Name: "console-container-0", Image: "alpine:latest", TTY: true, Stdin: true},
				},
			},
		}
		Expect(kubeClient.Create(context.TODO(), &pod)).To(Succeed())

		csl = newConsole(namespace.Name, "console", "template", "user@example.com", nil)
		csl.Status.Phase = workloadsv1alpha1.ConsoleRunning
		csl.Status.PodName = pod.Name
		mustCreateConsole(&csl)

		stdin, stdinWriter = io.Pipe()
		DeferCleanup(func() { _ = stdinWriter.Close() })

		stdout, stderr = &syncBuffer{}, &syncBuffer{}
		attaching = make(chan struct{}, 1)
	})

	setContainerState := func(state corev1.ContainerState) {
		Expect(kubeClient.Get(context.TODO(), client.ObjectKeyFromObject(&pod), &pod)).To(Succeed())

		// The pod's phase stays Running, as it does for a few seconds after the container
		// exits, so only the container's state can end the attach.
		pod.Status.Phase = corev1.PodRunning
		pod.Status.ContainerStatuses = []corev1.ContainerStatus{
			{Name: "console-container-0", Image: "alpine:latest", State: state},
		}
		Expect(kubeClient.Status().Update(context.TODO(), &pod)).To(Succeed())
	}

	terminated := func(exitCode int32, reason string) corev1.ContainerState {
		return corev1.ContainerState{
			Terminated: &corev1.ContainerStateTerminated{ExitCode: exitCode, Reason: reason},
		}
	}

	attach := func(ctx context.Context) error {
		return consoleRunner.Attach(ctx, runner.AttachOptions{
			Namespace:  namespace.Name,
			Name:       csl.Name,
			KubeConfig: cfg,
			IO:         runner.IOStreams{In: stdin, Out: stdout, ErrOut: stderr},
			Hook: runner.DefaultLifecycleHook{
				AttachingToPodFunc: func(*workloadsv1alpha1.Console) error {
					attaching <- struct{}{}
					return nil
				},
			},
		})
	}

	// Without a deadline a regression would wait forever for a pod phase envtest never changes.
	withDeadline := func() context.Context {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		DeferCleanup(cancel)
		return ctx
	}

	When("the container has already terminated", func() {
		Context("with a non-zero exit code", func() {
			BeforeEach(func() {
				setContainerState(terminated(3, "Error"))
			})

			It("shows the logs instead of attaching, and returns the exit code", func() {
				err := attach(withDeadline())

				var exitErr *runner.ContainerExitError
				Expect(errors.As(err, &exitErr)).To(BeTrue(), "expected a ContainerExitError, got %v", err)
				Expect(*exitErr).To(Equal(runner.ContainerExitError{
					Pod:       pod.Name,
					Container: "console-container-0",
					ExitCode:  3,
					Reason:    "Error",
				}))

				Expect(stderr.String()).To(ContainSubstring("Console has already finished, so showing its logs instead of attaching."))
				Expect(stderr.String()).NotTo(ContainSubstring("attach resulted in an error"))

				By("Never attaching, so there's no prompt to press return at")
				Expect(attaching).NotTo(Receive())
			})
		})

		Context("successfully", func() {
			BeforeEach(func() {
				setContainerState(terminated(0, "Completed"))
			})

			It("shows the logs instead of attaching, and succeeds", func() {
				Expect(attach(withDeadline())).To(Succeed())
				Expect(stderr.String()).To(ContainSubstring("Console has already finished"))
				Expect(attaching).NotTo(Receive())
			})
		})
	})

	When("the container terminates while we attach", func() {
		BeforeEach(func() {
			setContainerState(corev1.ContainerState{Running: &corev1.ContainerStateRunning{}})
		})

		It("returns the container's exit code without waiting for the pod's phase", func() {
			ctx := withDeadline()

			result := make(chan error, 1)
			go func() {
				defer GinkgoRecover()
				result <- attach(ctx)
			}()

			Eventually(attaching).Should(Receive())
			Consistently(result, 500*time.Millisecond).ShouldNot(Receive())

			setContainerState(terminated(4, "Error"))

			var err error
			Eventually(result, 10*time.Second).Should(Receive(&err))

			var exitErr *runner.ContainerExitError
			Expect(errors.As(err, &exitErr)).To(BeTrue(), "expected a ContainerExitError, got %v", err)
			Expect(exitErr.ExitCode).To(BeEquivalentTo(4))
			Expect(ctx.Err()).NotTo(HaveOccurred())

			By("Not reporting that it had already finished")
			Expect(stderr.String()).NotTo(ContainSubstring("Console has already finished"))
		})
	})
})
