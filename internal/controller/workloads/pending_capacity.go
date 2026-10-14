package controllers

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	workloadsv1alpha1 "github.com/gocardless/theatre/v5/api/workloads/v1alpha1"
)

const (
	// app.kubernetes.io/component value. Distinct from a real console pod so
	// the job-pod lookup does not treat this as the session.
	pendingCapacityComponent = "console-pending-capacity"

	// cluster-autoscaler.kubernetes.io/safe-to-evict. Copied when the template
	// sets it, so the placeholder is evicted on the same terms as the console pod.
	safeToEvictAnnotation = "cluster-autoscaler.kubernetes.io/safe-to-evict"

	// Used when the flag is enabled but the duration was left unset.
	defaultPendingCapacityTTL = 15 * time.Minute
)

// reconcilePendingCapacity creates a Job while the console is waiting for
// authorisation, and deletes it otherwise: once the console Job exists, once
// the console is stopped, and once the console itself expires.
//
// The Job's active deadline ends the placeholder. The Job object is left in
// place after that, so a later reconcile does not start another one while the
// console is still waiting. Deleting the console object still relies on the
// owner reference, because a console that is already being deleted is not
// reconciled.
func (r *ConsoleReconciler) reconcilePendingCapacity(ctx context.Context, logger logr.Logger, csl *workloadsv1alpha1.Console, template *workloadsv1alpha1.ConsoleTemplate) error {
	name := types.NamespacedName{
		Namespace: csl.Namespace,
		Name:      pendingCapacityJobName(csl.Name),
	}
	hold := r.EnablePendingCapacity && csl.PendingAuthorisation() && !csl.EligibleForGC()
	if !hold {
		return r.deletePendingCapacityJob(ctx, logger, name)
	}

	job, err := r.buildPendingCapacityJob(name, csl, template)
	if err != nil {
		return err
	}
	if err := controllerutil.SetControllerReference(csl, job, r.Scheme); err != nil {
		return errors.Wrap(err, "failed to set owner on pending capacity job")
	}

	existing := &batchv1.Job{}
	err = r.Get(ctx, name, existing)
	if apierrors.IsNotFound(err) {
		if err := r.Create(ctx, job); err != nil {
			return errors.Wrap(err, "failed to create pending capacity job")
		}
		logger.Info("Created pending capacity job", "event", EventSuccessfulCreate, "kind", "job", "job", job.Name)
		return nil
	}
	if err != nil {
		return errors.Wrap(err, "failed to get pending capacity job")
	}
	if !metav1.IsControlledBy(existing, csl) {
		return errors.Errorf("pending capacity job %s is not owned by this console", name)
	}
	// A finished job still occupies the name. Leave it, so the deadline is not
	// restarted by creating another.
	return nil
}

func (r *ConsoleReconciler) deletePendingCapacityJob(ctx context.Context, logger logr.Logger, name types.NamespacedName) error {
	grace := int64(0)
	policy := metav1.DeletePropagationBackground
	job := &batchv1.Job{ObjectMeta: metav1.ObjectMeta{Namespace: name.Namespace, Name: name.Name}}
	err := r.Delete(ctx, job, &client.DeleteOptions{
		GracePeriodSeconds: &grace,
		PropagationPolicy:  &policy,
	})
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return errors.Wrap(err, "failed to delete pending capacity job")
	}
	logger.Info("Deleted pending capacity job", "event", EventDelete, "kind", "job", "job", name.Name)
	return nil
}

func (r *ConsoleReconciler) buildPendingCapacityJob(name types.NamespacedName, csl *workloadsv1alpha1.Console, template *workloadsv1alpha1.ConsoleTemplate) (*batchv1.Job, error) {
	spec := template.Spec.Template.Spec.DeepCopy()
	if len(spec.Containers) == 0 || spec.Containers[0].Image == "" {
		return nil, errors.New("console template has no image for the pending capacity job")
	}
	// The session sidecar is part of the pod that will actually run, so the
	// placeholder has to reserve its resources too. The image that is pulled
	// is still the template's own image.
	if r.EnableSessionRecording {
		spec.Containers = append(spec.Containers, r.buildSidecarContainer(r.ConsoleIdBuilder.BuildId(csl)))
	}

	deadline := int64(r.pendingCapacityTTL().Seconds())
	backoff := int32(10)
	completions := int32(1)
	parallelism := int32(1)
	grace := int64(0)
	automount := false
	labels := map[string]string{
		"app.kubernetes.io/component": pendingCapacityComponent,
		"console-name":                sanitiseLabel(csl.Name),
	}
	podLabels := copyStringMap(labels)
	resources := corev1.ResourceRequirements{
		Requests: effectiveResources(spec, false),
		Limits:   effectiveResources(spec, true),
	}

	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name.Name,
			Namespace: name.Namespace,
			Labels:    labels,
		},
		Spec: batchv1.JobSpec{
			ActiveDeadlineSeconds: &deadline,
			// A preempted pod can be replaced. The deadline is counted from
			// when the job started, so a replacement does not extend it.
			BackoffLimit: &backoff,
			Completions:  &completions,
			Parallelism:  &parallelism,
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: podLabels},
				Spec: corev1.PodSpec{
					// Not the console service account: that account is the
					// workload's identity, and this pod only has to sit on a node.
					AutomountServiceAccountToken:  &automount,
					PriorityClassName:             r.PendingCapacityPriorityClass,
					TerminationGracePeriodSeconds: &grace,
					RestartPolicy:                 corev1.RestartPolicyNever,
					NodeSelector:                  copyStringMap(spec.NodeSelector),
					Tolerations:                   spec.Tolerations,
					Affinity:                      spec.Affinity,
					Containers: []corev1.Container{{
						Name:            "sleep",
						Image:           spec.Containers[0].Image,
						ImagePullPolicy: corev1.PullIfNotPresent,
						Command:         []string{"sleep"},
						Args:            []string{fmt.Sprintf("%d", deadline)},
						Resources:       resources,
					}},
				},
			},
		},
	}
	if v, ok := template.Spec.Template.Annotations[safeToEvictAnnotation]; ok {
		job.Spec.Template.Annotations = map[string]string{safeToEvictAnnotation: v}
	}
	return job, nil
}

func (r *ConsoleReconciler) pendingCapacityTTL() time.Duration {
	if r.PendingCapacityTTL > 0 {
		return r.PendingCapacityTTL
	}
	return defaultPendingCapacityTTL
}

// pendingCapacityJobName keeps the job name inside the 63 character label
// limit. The suffix differs from the console job, so its pods are not
// mistaken for the session.
func pendingCapacityJobName(consoleName string) string {
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
