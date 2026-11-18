package v1alpha1

import (
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// PAMRoleBindingConditionReady is true when the last sync both listed the entitlement's
	// grants from PAM and made the RoleBindings match them.
	PAMRoleBindingConditionReady = "Ready"

	PAMRoleBindingReasonSynced              = "Synced"
	PAMRoleBindingReasonEntitlementNotFound = "EntitlementNotFound"
	PAMRoleBindingReasonPAMUnreachable      = "PAMUnreachable"
	PAMRoleBindingReasonRoleBindingFailed   = "RoleBindingFailed"
	// PAMRoleBindingReasonEntitlementNotAllowed means the entitlement isn't in the Google
	// Cloud project rbac-manager runs in.
	PAMRoleBindingReasonEntitlementNotAllowed = "EntitlementNotAllowed"
)

type PAMRoleBindingSpec struct {
	// Entitlement is the full resource name of a PAM entitlement, e.g.
	// projects/my-project/locations/global/entitlements/my-entitlement. It must be in the
	// Google Cloud project rbac-manager runs in.
	// +kubebuilder:validation:Pattern=`^projects/[^/]+/locations/[^/]+/entitlements/[^/]+$`
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="Entitlement is immutable"
	Entitlement string `json:"entitlement"`

	// Namespaces are where each grant holder is bound. They're listed explicitly, so a new
	// namespace never gains access by accident.
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=100
	// +listType=set
	// +kubebuilder:validation:items:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	// +kubebuilder:validation:items:MaxLength=63
	Namespaces []string `json:"namespaces"`

	// RoleRef is the ClusterRole bound in each namespace.
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="RoleRef is immutable"
	// +kubebuilder:validation:XValidation:rule="self.kind == 'ClusterRole' && self.apiGroup == 'rbac.authorization.k8s.io'",message="RoleRef must be a ClusterRole"
	RoleRef rbacv1.RoleRef `json:"roleRef"`
}

type PAMGrant struct {
	// Subject is the grant's requester.
	Subject rbacv1.Subject `json:"subject"`
	// Grant is the full resource name of the PAM grant.
	Grant string `json:"grant"`
	// Approvers are everyone who approved the grant, in the order they approved.
	// +optional
	Approvers []string `json:"approvers,omitempty"`
	// EndsAt is when the grant ends. The RoleBindings are removed then, even if PAM can't
	// be reached.
	EndsAt metav1.Time `json:"endsAt"`
	// RoleBinding is the name of the grant's RoleBinding, which is the same in every
	// namespace.
	RoleBinding string `json:"roleBinding"`
	// Namespaces are where the subject is currently bound. This can fall short of
	// spec.namespaces when a binding fails.
	// +optional
	// +listType=set
	Namespaces []string `json:"namespaces,omitempty"`
}

type PAMRoleBindingStatus struct {
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// LastSyncTime is when the active grants were last listed from PAM successfully.
	// +optional
	LastSyncTime *metav1.Time `json:"lastSyncTime,omitempty"`

	// ActiveGrants are the grants currently bound. A subject with several grants appears
	// once for each.
	// +optional
	// +listType=map
	// +listMapKey=grant
	ActiveGrants []PAMGrant `json:"activeGrants,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion
// +kubebuilder:resource:scope=Cluster,shortName=prb
// +kubebuilder:printcolumn:name="Entitlement",type=string,JSONPath=`.spec.entitlement`,priority=1
// +kubebuilder:printcolumn:name="Role",type=string,JSONPath=`.spec.roleRef.name`
// +kubebuilder:printcolumn:name="Namespaces",type=string,JSONPath=`.spec.namespaces`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Reason",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].reason`
// +kubebuilder:printcolumn:name="Last sync",type=date,JSONPath=`.status.lastSyncTime`

// PAMRoleBinding binds a ClusterRole, in each of a list of namespaces, to everyone holding
// an active grant on a Google Cloud Privileged Access Manager (PAM) entitlement, until
// their grant ends.
type PAMRoleBinding struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   PAMRoleBindingSpec   `json:"spec,omitempty"`
	Status PAMRoleBindingStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

type PAMRoleBindingList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []PAMRoleBinding `json:"items"`
}

func init() {
	SchemeBuilder.Register(&PAMRoleBinding{}, &PAMRoleBindingList{})
}
