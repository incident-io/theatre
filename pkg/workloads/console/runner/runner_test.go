package runner

import (
	"io"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	workloadsv1alpha1 "github.com/gocardless/theatre/v5/api/workloads/v1alpha1"
)

var _ = Describe("checkPodState", func() {
	var (
		pod  *corev1.Pod
		done bool
		err  error
	)

	JustBeforeEach(func() {
		done, err = checkPodState(pod)
	})

	AssertNotDone := func() {
		It("Returns not done", func() {
			Expect(done).To(BeFalse())
			Expect(err).NotTo(HaveOccurred())
		})
	}

	AssertDone := func() {
		It("Returns done without error", func() {
			Expect(done).To(BeTrue())
			Expect(err).NotTo(HaveOccurred())
		})
	}

	When("pod is Running", func() {
		BeforeEach(func() {
			pod = &corev1.Pod{Status: corev1.PodStatus{Phase: corev1.PodRunning}}
		})

		AssertNotDone()
	})

	When("pod has Succeeded", func() {
		BeforeEach(func() {
			pod = &corev1.Pod{Status: corev1.PodStatus{Phase: corev1.PodSucceeded}}
		})

		AssertDone()
	})

	When("pod has Failed", func() {
		BeforeEach(func() {
			pod = &corev1.Pod{Status: corev1.PodStatus{
				Phase:   corev1.PodFailed,
				Message: "OOMKilled",
			}}
		})

		It("Returns done with error containing phase and message", func() {
			Expect(done).To(BeTrue())
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("Failed"))
			Expect(err.Error()).To(ContainSubstring("OOMKilled"))
		})
	})
})

var _ = Describe("checkConsoleState", func() {
	var (
		csl                  *workloadsv1alpha1.Console
		waitForAuthorisation bool
		done                 bool
		err                  error
	)

	BeforeEach(func() {
		waitForAuthorisation = true
		csl = &workloadsv1alpha1.Console{}
	})

	JustBeforeEach(func() {
		done, err = checkConsoleState(csl, waitForAuthorisation)
	})

	AssertNotDone := func() {
		It("Returns not done", func() {
			Expect(done).To(BeFalse())
			Expect(err).NotTo(HaveOccurred())
		})
	}

	AssertDone := func() {
		It("Returns done without error", func() {
			Expect(done).To(BeTrue())
			Expect(err).NotTo(HaveOccurred())
		})
	}

	When("console is Running", func() {
		BeforeEach(func() {
			csl.Status.Phase = workloadsv1alpha1.ConsoleRunning
		})

		AssertDone()
	})

	When("console is Stopped", func() {
		BeforeEach(func() {
			csl.Status.Phase = workloadsv1alpha1.ConsoleStopped
		})

		AssertDone()
	})

	When("console is Pending", func() {
		BeforeEach(func() {
			csl.Status.Phase = workloadsv1alpha1.ConsolePending
		})

		AssertNotDone()
	})

	When("console has empty phase", func() {
		AssertNotDone()
	})

	Describe("Pending Authorisation", func() {
		BeforeEach(func() {
			csl.Status.Phase = workloadsv1alpha1.ConsolePendingAuthorisation
		})

		When("waitForAuthorisation is true", func() {
			AssertNotDone()
		})

		When("waitForAuthorisation is false", func() {
			BeforeEach(func() {
				waitForAuthorisation = false
			})

			It("Returns done with errConsolePendingAuthorisation", func() {
				Expect(done).To(BeTrue())
				Expect(err).To(MatchError(errConsolePendingAuthorisation))
			})
		})
	})
})

var _ = Describe("rbHasSubject", func() {
	var rb *rbacv1.RoleBinding

	BeforeEach(func() {
		rb = &rbacv1.RoleBinding{
			Subjects: []rbacv1.Subject{
				{Kind: rbacv1.UserKind, Name: "alice"},
				{Kind: rbacv1.UserKind, Name: "bob"},
			},
		}
	})

	When("subject is present", func() {
		It("Returns true", func() {
			Expect(rbHasSubject(rb, "alice")).To(BeTrue())
		})
	})

	When("subject is not present", func() {
		It("Returns false", func() {
			Expect(rbHasSubject(rb, "charlie")).To(BeFalse())
		})
	})

	When("subjects list is empty", func() {
		BeforeEach(func() {
			rb.Subjects = nil
		})

		It("Returns false", func() {
			Expect(rbHasSubject(rb, "alice")).To(BeFalse())
		})
	})
})

var _ = Describe("checkAttachedContainerState", func() {
	var pod *corev1.Pod

	BeforeEach(func() {
		pod = &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "console-pod"},
			Status: corev1.PodStatus{
				Phase: corev1.PodRunning,
				ContainerStatuses: []corev1.ContainerStatus{
					{Name: "sidecar", State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}},
					{Name: "console", State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}},
				},
			},
		}
	})

	terminate := func(name string, exitCode int32) {
		for i := range pod.Status.ContainerStatuses {
			if pod.Status.ContainerStatuses[i].Name == name {
				pod.Status.ContainerStatuses[i].State = corev1.ContainerState{
					Terminated: &corev1.ContainerStateTerminated{ExitCode: exitCode, Reason: "Error"},
				}
			}
		}
	}

	It("keeps watching while the container runs", func() {
		done, err := checkAttachedContainerState(pod, "console")
		Expect(done).To(BeFalse())
		Expect(err).NotTo(HaveOccurred())
	})

	It("ignores containers we didn't attach to", func() {
		terminate("sidecar", 1)

		done, err := checkAttachedContainerState(pod, "console")
		Expect(done).To(BeFalse())
		Expect(err).NotTo(HaveOccurred())
	})

	It("is done once the container exits 0, before the pod's phase changes", func() {
		terminate("console", 0)

		done, err := checkAttachedContainerState(pod, "console")
		Expect(done).To(BeTrue())
		Expect(err).NotTo(HaveOccurred())
	})

	It("returns the exit code of a container that failed", func() {
		terminate("console", 2)

		done, err := checkAttachedContainerState(pod, "console")
		Expect(done).To(BeTrue())
		Expect(err).To(Equal(&ContainerExitError{Pod: "console-pod", Container: "console", ExitCode: 2, Reason: "Error"}))
		Expect(err).To(MatchError("console container console in pod console-pod exited with code 2 (Error)"))
	})

	It("falls back to the pod's phase", func() {
		pod.Status.Phase = corev1.PodSucceeded

		done, err := checkAttachedContainerState(pod, "console")
		Expect(done).To(BeTrue())
		Expect(err).NotTo(HaveOccurred())
	})
})

// blockingReader stands in for a terminal: each Read waits until the test types a line.
type blockingReader struct {
	lines chan string
}

func (r blockingReader) Read(p []byte) (int, error) {
	line, ok := <-r.lines
	if !ok {
		return 0, io.EOF
	}
	return copy(p, line), nil
}

var _ = Describe("stdinGate", func() {
	var (
		terminal blockingReader
		gate     *stdinGate
	)

	BeforeEach(func() {
		terminal = blockingReader{lines: make(chan string, 1)}
		gate = newStdinGate(terminal)
	})

	It("passes input through while the console runs", func() {
		terminal.lines <- "ls\n"

		buf := make([]byte, 16)
		n, err := gate.Read(buf)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(buf[:n])).To(Equal("ls\n"))
	})

	It("ends the copy, without forwarding it, when return is pressed after the console finished", func() {
		read := make(chan error, 1)
		var forwarded strings.Builder
		go func() {
			// What client-go's copyStdin does with the reader.
			_, err := io.Copy(&forwarded, gate)
			read <- err
		}()

		// The copy is blocked reading the terminal when the console finishes.
		Consistently(read).ShouldNot(Receive())
		gate.Close()

		terminal.lines <- "\n"
		Eventually(read).Should(Receive(BeNil()))
		Expect(forwarded.String()).To(BeEmpty())
	})

	It("doesn't read the terminal at all once closed", func() {
		gate.Close()

		n, err := gate.Read(make([]byte, 16))
		Expect(n).To(BeZero())
		Expect(err).To(Equal(io.EOF))
	})
})
