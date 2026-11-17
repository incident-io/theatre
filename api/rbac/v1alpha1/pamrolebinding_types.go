package v1alpha1

import (
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// PAMRoleBindingConditionSynced is true when the last attempt to list the entitlement's
	// grants from PAM, and to make the RoleBindings match them, succeeded.
	PAMRoleBindingConditionSynced = "Synced"

	// Reasons for the Synced condition.
	PAMRoleBindingReasonSynced              = "Synced"
	PAMRoleBindingReasonEntitlementNotFound = "EntitlementNotFound"
	PAMRoleBindingReasonPAMUnreachable      = "PAMUnreachable"
	PAMRoleBindingReasonRoleBindingFailed   = "RoleBindingFailed"
)

// PAMRoleBindingSpec defines the desired state of PAMRoleBinding
type PAMRoleBindingSpec struct {
	// Entitlement is the full resource name of a Google Cloud Privileged Access Manager
	// (PAM) entitlement. Every user with an active grant on it is bound to RoleRef in this
	// namespace, for as long as the grant lasts.
	// +kubebuilder:validation:Pattern=`^(projects|folders|organizations)/[^/]+/locations/[^/]+/entitlements/[^/]+$`
	Entitlement string `json:"entitlement"`

	// RoleRef is the Role or ClusterRole to bind each grant holder to.
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="RoleRef is immutable"
	RoleRef rbacv1.RoleRef `json:"roleRef"`
}

// PAMGrant is an active PAM grant that this PAMRoleBinding has bound.
type PAMGrant struct {
	// User is the email address of the grant's requester, and the RoleBinding's subject.
	User string `json:"user"`
	// Grant is the full resource name of the PAM grant.
	Grant string `json:"grant"`
	// Approver is the email address of whoever approved the grant, if it needed approval.
	// +optional
	Approver string `json:"approver,omitempty"`
	// EndsAt is when the grant ends. The RoleBinding is removed then, even if PAM can't be
	// reached.
	EndsAt metav1.Time `json:"endsAt"`
	// RoleBinding is the name of the RoleBinding that binds the user.
	RoleBinding string `json:"roleBinding"`
}

// PAMRoleBindingStatus defines the observed state of PAMRoleBinding
type PAMRoleBindingStatus struct {
	// Conditions describe the last sync with PAM.
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// LastSyncTime is when the active grants were last listed from PAM successfully.
	// +optional
	LastSyncTime *metav1.Time `json:"lastSyncTime,omitempty"`

	// ActiveGrants are the grants currently bound, one per user.
	// +optional
	ActiveGrants []PAMGrant `json:"activeGrants,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion
// +kubebuilder:resource:shortName=prb
// +kubebuilder:printcolumn:name="Entitlement",type=string,JSONPath=`.spec.entitlement`,priority=1
// +kubebuilder:printcolumn:name="Role",type=string,JSONPath=`.spec.roleRef.name`
// +kubebuilder:printcolumn:name="Synced",type=string,JSONPath=`.status.conditions[?(@.type=="Synced")].status`
// +kubebuilder:printcolumn:name="Reason",type=string,JSONPath=`.status.conditions[?(@.type=="Synced")].reason`
// +kubebuilder:printcolumn:name="Last sync",type=date,JSONPath=`.status.lastSyncTime`

// PAMRoleBinding binds a role in its namespace to every user holding an active grant on a
// Google Cloud Privileged Access Manager (PAM) entitlement. PAM handles requests,
// approvals and expiry; theatre keeps one RoleBinding per grant holder, and removes it
// when the grant ends.
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
