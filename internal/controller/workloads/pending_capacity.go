package controllers

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	workloadsv1alpha1 "github.com/gocardless/theatre/v5/api/workloads/v1alpha1"
)

const (
	// How often to look again while a capacity pod is held, so one that
	// disappeared is replaced before the console's before-running TTL.
	pendingCapacityRecheck = 30 * time.Second

	// app.kubernetes.io/component value. Distinct from a real console pod so
	// dashboards and the job-pod lookup do not treat this as the session.
	pendingCapacityComponent = "console-pending-capacity"

	// cluster-autoscaler.kubernetes.io/safe-to-evict. Copied from the template
	// when the template sets it: on GKE Autopilot that annotation is what puts
	// the pod on an extended-duration node, and it stops the autoscaler
	// evicting the placeholder to scale the node away.
	safeToEvictAnnotation = "cluster-autoscaler.kubernetes.io/safe-to-evict"

	// Defaults match the pause image and the existing spare-capacity
	// PriorityClass (value -9, preemptionPolicy Never). A normal pod, priority
	// 0, can preempt this one. This pod never preempts anything else.
	DefaultPendingCapacityImage         = "registry.k8s.io/pause:3.10"
	DefaultPendingCapacityPriorityClass = "capacity-spare-consistent"
)

// reconcilePendingCapacity creates the placeholder while the console is
// waiting for authorisation, and deletes it otherwise: once the job exists,
// once the console is stopped, and before an expired console is removed.
// Deleting the console object itself still relies on the owner reference,
// because a console that is already being deleted is not reconciled.
func (r *ConsoleReconciler) reconcilePendingCapacity(ctx context.Context, logger logr.Logger, csl *workloadsv1alpha1.Console, template *workloadsv1alpha1.ConsoleTemplate) error {
	name := types.NamespacedName{
		Namespace: csl.Namespace,
		Name:      pendingCapacityPodName(csl.Name),
	}
	hold := r.EnablePendingCapacity && csl.PendingAuthorisation() && !csl.EligibleForGC()
	if !hold {
		return r.deletePendingCapacityPod(ctx, logger, name)
	}

	pod := r.buildPendingCapacityPod(name, csl, template)
	if err := controllerutil.SetControllerReference(csl, pod, r.Scheme); err != nil {
		return errors.Wrap(err, "failed to set owner on pending capacity pod")
	}

	existing := &corev1.Pod{}
	err := r.Get(ctx, name, existing)
	if apierrors.IsNotFound(err) {
		if err := r.Create(ctx, pod); err != nil {
			return errors.Wrap(err, "failed to create pending capacity pod")
		}
		logger.Info("Created pending capacity pod", "event", EventSuccessfulCreate, "kind", "pod", "pod", pod.Name)
		return nil
	}
	if err != nil {
		return errors.Wrap(err, "failed to get pending capacity pod")
	}
	if !metav1.IsControlledBy(existing, csl) {
		return errors.Errorf("pending capacity pod %s is not owned by this console", name)
	}
	// Pod specs are immutable, and a console does not change shape while it
	// waits. Leave the pod that is already held.
	return nil
}

func (r *ConsoleReconciler) deletePendingCapacityPod(ctx context.Context, logger logr.Logger, name types.NamespacedName) error {
	grace := int64(0)
	policy := metav1.DeletePropagationBackground
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: name.Namespace, Name: name.Name}}
	err := r.Delete(ctx, pod, &client.DeleteOptions{
		GracePeriodSeconds: &grace,
		PropagationPolicy:  &policy,
	})
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return errors.Wrap(err, "failed to delete pending capacity pod")
	}
	logger.Info("Deleted pending capacity pod", "event", EventDelete, "kind", "pod", "pod", name.Name)
	return nil
}

func (r *ConsoleReconciler) buildPendingCapacityPod(name types.NamespacedName, csl *workloadsv1alpha1.Console, template *workloadsv1alpha1.ConsoleTemplate) *corev1.Pod {
	spec := template.Spec.Template.Spec.DeepCopy()
	// The session sidecar is part of the pod that will actually run, so the
	// placeholder has to reserve its resources too.
	if r.EnableSessionRecording {
		spec.Containers = append(spec.Containers, r.buildSidecarContainer(r.ConsoleIdBuilder.BuildId(csl)))
	}

	grace := int64(0)
	automount := false
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name.Name,
			Namespace: name.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/component": pendingCapacityComponent,
				"console-name":                sanitiseLabel(csl.Name),
			},
		},
		Spec: corev1.PodSpec{
			// Not the console service account: that account is the workload's
			// identity, and this pod only has to sit on a node.
			AutomountServiceAccountToken:  &automount,
			PriorityClassName:             r.pendingCapacityPriorityClass(),
			TerminationGracePeriodSeconds: &grace,
			RestartPolicy:                 corev1.RestartPolicyAlways,
			NodeSelector:                  copyStringMap(spec.NodeSelector),
			Tolerations:                   spec.Tolerations,
			Affinity:                      spec.Affinity,
			Containers: []corev1.Container{{
				Name:            "pause",
				Image:           r.pendingCapacityImage(),
				ImagePullPolicy: corev1.PullIfNotPresent,
				Resources: corev1.ResourceRequirements{
					Requests: effectiveResources(spec, false),
					Limits:   effectiveResources(spec, true),
				},
			}},
		},
	}
	if v, ok := template.Spec.Template.Annotations[safeToEvictAnnotation]; ok {
		pod.Annotations = map[string]string{safeToEvictAnnotation: v}
	}
	return pod
}

func (r *ConsoleReconciler) pendingCapacityImage() string {
	if r.PendingCapacityImage != "" {
		return r.PendingCapacityImage
	}
	return DefaultPendingCapacityImage
}

func (r *ConsoleReconciler) pendingCapacityPriorityClass() string {
	if r.PendingCapacityPriorityClass != "" {
		return r.PendingCapacityPriorityClass
	}
	return DefaultPendingCapacityPriorityClass
}

// pendingCapacityPodName keeps the pod name inside the 63 character label
// limit, same constraint as the console job name.
func pendingCapacityPodName(consoleName string) string {
	return fmt.Sprintf("%s-capacity", truncateString(consoleName, 54))
}

// effectiveResources is the request (or limit) the scheduler uses for the
// pod: the sum of the app containers, plus sidecar init containers, and at
// least the largest sequential init container. That is the hole the real
// console pod needs.
func effectiveResources(spec *corev1.PodSpec, limits bool) corev1.ResourceList {
	pick := func(c corev1.Container) corev1.ResourceList {
		if limits {
			return c.Resources.Limits
		}
		return c.Resources.Requests
	}

	total := corev1.ResourceList{}
	for _, c := range spec.Containers {
		addResourceList(total, pick(c))
	}
	initMax := corev1.ResourceList{}
	for _, c := range spec.InitContainers {
		if isSidecarInit(c) {
			addResourceList(total, pick(c))
			continue
		}
		for name, q := range pick(c) {
			cur, ok := initMax[name]
			if !ok || q.Cmp(cur) > 0 {
				initMax[name] = q.DeepCopy()
			}
		}
	}
	for name, q := range initMax {
		cur, ok := total[name]
		if !ok || q.Cmp(cur) > 0 {
			total[name] = q.DeepCopy()
		}
	}
	if len(total) == 0 {
		return nil
	}
	return total
}

func isSidecarInit(c corev1.Container) bool {
	return c.RestartPolicy != nil && *c.RestartPolicy == corev1.ContainerRestartPolicyAlways
}

func addResourceList(dst, src corev1.ResourceList) {
	for name, q := range src {
		if q.IsZero() {
			continue
		}
		q = q.DeepCopy()
		if cur, ok := dst[name]; ok {
			cur.Add(q)
			dst[name] = cur
			continue
		}
		dst[name] = q
	}
}

func copyStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
