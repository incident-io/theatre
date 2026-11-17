package pamrolebinding

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	rbacv1alpha1 "github.com/gocardless/theatre/v5/api/rbac/v1alpha1"
)

const (
	// LabelPAMRoleBinding names the PAMRoleBinding that owns a RoleBinding, so the
	// controller can find its own bindings with a label selector.
	LabelPAMRoleBinding = "rbac.crd.gocardless.com/pam-role-binding"

	annotationPrefix = "pam.rbac.crd.gocardless.com/"
	// AnnotationGrant is the grant's full resource name, for `gcloud pam grants describe`.
	AnnotationGrant = annotationPrefix + "grant"
	// AnnotationGrantID is the grant's ID, for searching audit logs.
	AnnotationGrantID = annotationPrefix + "grant-id"
	// AnnotationApprover is the approver's email, absent if no approval was needed.
	AnnotationApprover = annotationPrefix + "approver"
	// AnnotationRequester is the user's email. Labels can't hold an '@'.
	AnnotationRequester = annotationPrefix + "requester"
	// AnnotationEndsAt is when the grant ends, in RFC 3339. The controller deletes the
	// RoleBinding at this time even if PAM can't be reached.
	AnnotationEndsAt = annotationPrefix + "ends-at"

	EventGrantBound     = "GrantBound"
	EventGrantExpired   = "GrantExpired"
	EventGrantWithdrawn = "GrantWithdrawn"
	EventSyncFailed     = "SyncFailed"

	// maxBackoff caps how long we wait between attempts while PAM is failing. Expiry is
	// scheduled separately, so this only delays new grants and early withdrawals.
	maxBackoff = time.Minute
)

// Reconciler keeps one RoleBinding per user with an active grant on a PAMRoleBinding's
// entitlement.
//
// It needs create, delete, get, list and watch on RoleBindings, and bind on the roles it
// hands out. It never updates a RoleBinding: one that's wrong is deleted and recreated.
type Reconciler struct {
	client.Client
	Log      logr.Logger
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder
	Grants   GrantLister
	// RefreshInterval is how often each PAMRoleBinding is synced with PAM.
	RefreshInterval time.Duration
	// Now is overridable for tests.
	Now func() time.Time

	mu       sync.Mutex
	failures map[types.NamespacedName]int
}

func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.Now == nil {
		r.Now = time.Now
	}
	r.failures = map[types.NamespacedName]int{}

	return ctrl.NewControllerManagedBy(mgr).
		For(&rbacv1alpha1.PAMRoleBinding{}).
		// Recreate a binding promptly if someone deletes it while its grant is active.
		Owns(&rbacv1.RoleBinding{}).
		Complete(r)
}

func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := r.Log.WithValues("pamrolebinding", req.NamespacedName)

	prb := &rbacv1alpha1.PAMRoleBinding{}
	if err := r.Get(ctx, req.NamespacedName, prb); err != nil {
		if apierrors.IsNotFound(err) {
			// Owned RoleBindings are garbage collected with their owner.
			forgetMetrics(req.Namespace, req.Name)
			r.resetFailures(req.NamespacedName)
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}
	if !prb.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}

	now := r.Now()

	owned, err := r.ownedRoleBindings(ctx, prb)
	if err != nil {
		return ctrl.Result{}, err
	}

	grants, listErr := r.Grants.ListActiveGrants(ctx, prb.Spec.Entitlement)
	if listErr != nil {
		return r.syncFailed(ctx, logger, prb, owned, now, listErr)
	}

	desired := desiredBindings(prb, grants, now)

	var bindErrs []error
	for name, rb := range owned {
		want, ok := desired[name]
		if ok && matches(rb, want) {
			continue
		}
		reason := EventGrantWithdrawn
		if ok {
			reason = "" // replaced by a newer grant, recreated below
		} else if expired(rb, now) {
			reason = EventGrantExpired
		}
		if err := r.deleteRoleBinding(ctx, prb, rb, reason); err != nil {
			bindErrs = append(bindErrs, err)
			continue
		}
		delete(owned, name)
	}

	for name, want := range desired {
		if _, ok := owned[name]; ok {
			continue
		}
		if err := r.createRoleBinding(ctx, prb, want); err != nil {
			bindErrs = append(bindErrs, err)
		}
	}

	prb.Status.LastSyncTime = &metav1.Time{Time: now}
	prb.Status.ActiveGrants = activeGrantStatus(desired)
	lastSyncTimestamp.WithLabelValues(prb.Namespace, prb.Name).Set(float64(now.Unix()))
	entitlementNotFound.WithLabelValues(prb.Namespace, prb.Name).Set(0)
	activeGrants.WithLabelValues(prb.Namespace, prb.Name).Set(float64(len(desired)))

	if len(bindErrs) > 0 {
		err := errors.Join(bindErrs...)
		r.setCondition(prb, metav1.ConditionFalse, rbacv1alpha1.PAMRoleBindingReasonRoleBindingFailed, err.Error())
		r.Recorder.Event(prb, corev1.EventTypeWarning, EventSyncFailed, err.Error())
		if statusErr := r.Status().Update(ctx, prb); statusErr != nil {
			logger.Error(statusErr, "failed to update status")
		}
		return ctrl.Result{RequeueAfter: r.backoff(req.NamespacedName, desired, now)}, nil
	}

	r.resetFailures(req.NamespacedName)
	r.setCondition(prb, metav1.ConditionTrue, rbacv1alpha1.PAMRoleBindingReasonSynced,
		fmt.Sprintf("%d active grant(s) bound", len(desired)))
	if err := r.Status().Update(ctx, prb); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{RequeueAfter: r.nextSync(desired, now, r.RefreshInterval)}, nil
}

// syncFailed handles a failed list from PAM. A failed list says nothing about which
// grants are active, so it never removes access early: only bindings whose grant has
// already ended are deleted.
func (r *Reconciler) syncFailed(ctx context.Context, logger logr.Logger, prb *rbacv1alpha1.PAMRoleBinding, owned map[string]*rbacv1.RoleBinding, now time.Time, listErr error) (ctrl.Result, error) {
	logger.Error(listErr, "failed to list grants from PAM")

	reason := rbacv1alpha1.PAMRoleBindingReasonPAMUnreachable
	notFound := 0.0
	if errors.Is(listErr, ErrEntitlementNotFound) {
		reason = rbacv1alpha1.PAMRoleBindingReasonEntitlementNotFound
		notFound = 1
	}
	entitlementNotFound.WithLabelValues(prb.Namespace, prb.Name).Set(notFound)

	remaining := map[string]*rbacv1.RoleBinding{}
	for name, rb := range owned {
		if expired(rb, now) {
			if err := r.deleteRoleBinding(ctx, prb, rb, EventGrantExpired); err != nil {
				logger.Error(err, "failed to delete expired RoleBinding", "rolebinding", name)
			} else {
				continue
			}
		}
		remaining[name] = rb
	}

	prb.Status.ActiveGrants = activeGrantStatus(remaining)
	activeGrants.WithLabelValues(prb.Namespace, prb.Name).Set(float64(len(remaining)))
	r.setCondition(prb, metav1.ConditionFalse, reason, listErr.Error())
	r.Recorder.Event(prb, corev1.EventTypeWarning, EventSyncFailed, listErr.Error())
	if err := r.Status().Update(ctx, prb); err != nil {
		logger.Error(err, "failed to update status")
	}

	return ctrl.Result{RequeueAfter: r.backoff(types.NamespacedName{Namespace: prb.Namespace, Name: prb.Name}, remaining, now)}, nil
}

// backoff doubles the wait after each consecutive failure, up to maxBackoff, but always
// wakes up in time to remove the next binding that expires.
func (r *Reconciler) backoff(key types.NamespacedName, bindings map[string]*rbacv1.RoleBinding, now time.Time) time.Duration {
	r.mu.Lock()
	r.failures[key]++
	n := r.failures[key]
	r.mu.Unlock()

	wait := r.RefreshInterval
	for i := 1; i < n && wait < maxBackoff; i++ {
		wait *= 2
	}
	if wait > maxBackoff {
		wait = maxBackoff
	}

	return r.nextSync(bindings, now, wait)
}

func (r *Reconciler) resetFailures(key types.NamespacedName) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.failures, key)
}

// nextSync returns the sooner of wait and the moment the next binding expires.
func (r *Reconciler) nextSync(bindings map[string]*rbacv1.RoleBinding, now time.Time, wait time.Duration) time.Duration {
	for _, rb := range bindings {
		if endsAt, ok := endsAt(rb); ok {
			if until := endsAt.Sub(now) + time.Second; until < wait {
				wait = until
			}
		}
	}
	if wait < time.Second {
		wait = time.Second
	}
	return wait
}

func (r *Reconciler) ownedRoleBindings(ctx context.Context, prb *rbacv1alpha1.PAMRoleBinding) (map[string]*rbacv1.RoleBinding, error) {
	list := &rbacv1.RoleBindingList{}
	if err := r.List(ctx, list, client.InNamespace(prb.Namespace), client.MatchingLabels{LabelPAMRoleBinding: prb.Name}); err != nil {
		return nil, fmt.Errorf("listing RoleBindings: %w", err)
	}

	owned := map[string]*rbacv1.RoleBinding{}
	for i := range list.Items {
		rb := &list.Items[i]
		if metav1.IsControlledBy(rb, prb) {
			owned[rb.Name] = rb
		}
	}
	return owned, nil
}

func (r *Reconciler) createRoleBinding(ctx context.Context, prb *rbacv1alpha1.PAMRoleBinding, rb *rbacv1.RoleBinding) error {
	if err := controllerutil.SetControllerReference(prb, rb, r.Scheme); err != nil {
		return err
	}
	if err := r.Create(ctx, rb); err != nil {
		if apierrors.IsAlreadyExists(err) {
			return fmt.Errorf("RoleBinding %s already exists and isn't owned by this PAMRoleBinding", rb.Name)
		}
		return fmt.Errorf("creating RoleBinding %s: %w", rb.Name, err)
	}

	r.Recorder.Eventf(prb, corev1.EventTypeNormal, EventGrantBound,
		"Bound %s to %s %s until %s (grant %s)", rb.Annotations[AnnotationRequester],
		rb.RoleRef.Kind, rb.RoleRef.Name, rb.Annotations[AnnotationEndsAt], rb.Annotations[AnnotationGrantID])
	return nil
}

func (r *Reconciler) deleteRoleBinding(ctx context.Context, prb *rbacv1alpha1.PAMRoleBinding, rb *rbacv1.RoleBinding, reason string) error {
	err := r.Delete(ctx, rb, client.Preconditions{UID: &rb.UID})
	if err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("deleting RoleBinding %s: %w", rb.Name, err)
	}

	if reason != "" {
		r.Recorder.Eventf(prb, corev1.EventTypeNormal, reason,
			"Unbound %s (grant %s)", rb.Annotations[AnnotationRequester], rb.Annotations[AnnotationGrantID])
	}
	return nil
}

func (r *Reconciler) setCondition(prb *rbacv1alpha1.PAMRoleBinding, status metav1.ConditionStatus, reason, message string) {
	meta.SetStatusCondition(&prb.Status.Conditions, metav1.Condition{
		Type:               rbacv1alpha1.PAMRoleBindingConditionSynced,
		Status:             status,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: prb.Generation,
	})
}

// desiredBindings works out one RoleBinding per user with an active grant. A user with
// several grants gets one binding, for the grant that ends last.
func desiredBindings(prb *rbacv1alpha1.PAMRoleBinding, grants []Grant, now time.Time) map[string]*rbacv1.RoleBinding {
	latest := map[string]Grant{}
	for _, grant := range grants {
		if grant.Requester == "" || !grant.EndsAt.After(now) {
			continue
		}
		if current, ok := latest[grant.Requester]; !ok || grant.EndsAt.After(current.EndsAt) {
			latest[grant.Requester] = grant
		}
	}

	users := make([]string, 0, len(latest))
	for user := range latest {
		users = append(users, user)
	}
	names := roleBindingNames(prb.Name, users)

	desired := map[string]*rbacv1.RoleBinding{}
	for user, grant := range latest {
		annotations := map[string]string{
			AnnotationGrant:     grant.Name,
			AnnotationGrantID:   grant.ID(),
			AnnotationRequester: user,
			AnnotationEndsAt:    grant.EndsAt.UTC().Format(time.RFC3339),
		}
		if grant.Approver != "" {
			annotations[AnnotationApprover] = grant.Approver
		}

		desired[names[user]] = &rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:        names[user],
				Namespace:   prb.Namespace,
				Labels:      map[string]string{LabelPAMRoleBinding: prb.Name},
				Annotations: annotations,
			},
			RoleRef: prb.Spec.RoleRef,
			Subjects: []rbacv1.Subject{{
				APIGroup: rbacv1.GroupName,
				Kind:     rbacv1.UserKind,
				Name:     user,
			}},
		}
	}
	return desired
}

// matches reports whether an existing binding already reflects the desired grant.
func matches(existing, desired *rbacv1.RoleBinding) bool {
	if existing.RoleRef != desired.RoleRef || len(existing.Subjects) != 1 || existing.Subjects[0] != desired.Subjects[0] {
		return false
	}
	for _, key := range []string{AnnotationGrant, AnnotationApprover, AnnotationRequester, AnnotationEndsAt} {
		if existing.Annotations[key] != desired.Annotations[key] {
			return false
		}
	}
	return true
}

func endsAt(rb *rbacv1.RoleBinding) (time.Time, bool) {
	t, err := time.Parse(time.RFC3339, rb.Annotations[AnnotationEndsAt])
	return t, err == nil
}

// expired reports whether a binding's grant has ended. A binding we can't read an end
// time from is treated as expired, so it can never outstay its grant.
func expired(rb *rbacv1.RoleBinding, now time.Time) bool {
	t, ok := endsAt(rb)
	return !ok || !t.After(now)
}

func activeGrantStatus(bindings map[string]*rbacv1.RoleBinding) []rbacv1alpha1.PAMGrant {
	out := make([]rbacv1alpha1.PAMGrant, 0, len(bindings))
	for name, rb := range bindings {
		t, _ := endsAt(rb)
		out = append(out, rbacv1alpha1.PAMGrant{
			User:        rb.Annotations[AnnotationRequester],
			Grant:       rb.Annotations[AnnotationGrant],
			Approver:    rb.Annotations[AnnotationApprover],
			EndsAt:      metav1.Time{Time: t},
			RoleBinding: name,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].User < out[j].User })
	return out
}
