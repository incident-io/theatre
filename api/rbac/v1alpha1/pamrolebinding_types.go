package v1alpha1

import (
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// PAMRoleBindingConditionReady is true when the last attempt to list the entitlement's
	// grants from PAM, and to make the RoleBindings match them, succeeded.
	PAMRoleBindingConditionReady = "Ready"

	// Reasons for the Ready condition.
	PAMRoleBindingReasonSynced              = "Synced"
	PAMRoleBindingReasonEntitlementNotFound = "EntitlementNotFound"
	PAMRoleBindingReasonPAMUnreachable      = "PAMUnreachable"
	PAMRoleBindingReasonRoleBindingFailed   = "RoleBindingFailed"
	// PAMRoleBindingReasonEntitlementNotAllowed means the entitlement isn't in the Google
	// Cloud project rbac-manager runs in.
	PAMRoleBindingReasonEntitlementNotAllowed = "EntitlementNotAllowed"
)

// PAMRoleBindingSpec defines the desired state of PAMRoleBinding
type PAMRoleBindingSpec struct {
	// Entitlement is the full resource name of a Google Cloud Privileged Access Manager
	// (PAM) entitlement. Every principal with an active grant on it is bound to RoleRef in
	// each of Namespaces, for as long as the grant lasts. rbac-manager only honours
	// entitlements in the Google Cloud project it runs in.
	//
	// It's immutable: pointing a PAMRoleBinding at another entitlement would keep the old
	// one's bindings until they expire. Recreate the PAMRoleBinding instead.
	// +kubebuilder:validation:Pattern=`^projects/[^/]+/locations/[^/]+/entitlements/[^/]+$`
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="Entitlement is immutable"
	Entitlement string `json:"entitlement"`

	// Namespaces are where each grant holder is bound. There's deliberately no way to
	// select all namespaces, or namespaces by label, so a new namespace never gains access
	// by accident. Namespaces can be added and removed: bindings follow.
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=100
	// +listType=set
	// +kubebuilder:validation:items:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	// +kubebuilder:validation:items:MaxLength=63
	Namespaces []string `json:"namespaces"`

	// RoleRef is the ClusterRole to bind each grant holder to, in each namespace. It must
	// be a ClusterRole, because a Role only exists in one namespace.
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="RoleRef is immutable"
	// +kubebuilder:validation:XValidation:rule="self.kind == 'ClusterRole' && self.apiGroup == 'rbac.authorization.k8s.io'",message="RoleRef must be a ClusterRole"
	RoleRef rbacv1.RoleRef `json:"roleRef"`
}

// PAMGrant is an active PAM grant that this PAMRoleBinding has bound.
type PAMGrant struct {
	// Subject is who the grant is bound to: the grant's requester, as a RoleBinding
	// subject.
	Subject rbacv1.Subject `json:"subject"`
	// Grant is the full resource name of the PAM grant.
	Grant string `json:"grant"`
	// Approvers are everyone who approved the grant, in order. Empty if it needed no
	// approval.
	// +optional
	Approvers []string `json:"approvers,omitempty"`
	// EndsAt is when the grant ends. The RoleBindings are removed then, even if PAM can't
	// be reached.
	EndsAt metav1.Time `json:"endsAt"`
	// RoleBinding is the name of the RoleBinding that binds the subject. It's the same in
	// every namespace.
	RoleBinding string `json:"roleBinding"`
	// Namespaces are where the subject is currently bound.
	// +optional
	// +listType=set
	Namespaces []string `json:"namespaces,omitempty"`
}

// PAMRoleBindingStatus defines the observed state of PAMRoleBinding
type PAMRoleBindingStatus struct {
	// ObservedGeneration is the spec generation the status reflects.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Conditions describe the last sync with PAM. Ready is true when it succeeded.
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// LastSyncTime is when the active grants were last listed from PAM successfully.
	// +optional
	LastSyncTime *metav1.Time `json:"lastSyncTime,omitempty"`

	// ActiveGrants are the grants currently bound, one per subject.
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

// PAMRoleBinding binds a ClusterRole, in each of a list of namespaces, to every principal
// holding an active grant on a Google Cloud Privileged Access Manager (PAM) entitlement.
// PAM handles requests, approvals and expiry; theatre keeps one RoleBinding per grant
// holder per namespace, and removes them when the grant ends.
//
// It's cluster-scoped, so it can own RoleBindings in several namespaces, and so only
// those with cluster-level permissions can create one.
type PAMRoleBinding struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   PAMRoleBindingSpec   `json:"spec,omitempty"`
	Status PAMRoleBindingStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// PAMRoleBindingList contains a list of PAMRoleBinding
type PAMRoleBindingList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []PAMRoleBinding `json:"items"`
}

func init() {
	SchemeBuilder.Register(&PAMRoleBinding{}, &PAMRoleBindingList{})
}
