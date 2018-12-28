// +build !ignore_autogenerated

/*
Copyright The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Code generated by deepcopy-gen. DO NOT EDIT.

package v1alpha1

import (
	time "time"

	v1 "k8s.io/api/rbac/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DirectoryRoleBinding) DeepCopyInto(out *DirectoryRoleBinding) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	if in.Subjects != nil {
		in, out := &in.Subjects, &out.Subjects
		*out = make([]v1.Subject, len(*in))
		copy(*out, *in)
	}
	out.RoleRef = in.RoleRef
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DirectoryRoleBinding.
func (in *DirectoryRoleBinding) DeepCopy() *DirectoryRoleBinding {
	if in == nil {
		return nil
	}
	out := new(DirectoryRoleBinding)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *DirectoryRoleBinding) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DirectoryRoleBindingList) DeepCopyInto(out *DirectoryRoleBindingList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	out.ListMeta = in.ListMeta
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]DirectoryRoleBinding, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DirectoryRoleBindingList.
func (in *DirectoryRoleBindingList) DeepCopy() *DirectoryRoleBindingList {
	if in == nil {
		return nil
	}
	out := new(DirectoryRoleBindingList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *DirectoryRoleBindingList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *SudoRoleBinding) DeepCopyInto(out *SudoRoleBinding) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new SudoRoleBinding.
func (in *SudoRoleBinding) DeepCopy() *SudoRoleBinding {
	if in == nil {
		return nil
	}
	out := new(SudoRoleBinding)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *SudoRoleBinding) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *SudoRoleBindingGrant) DeepCopyInto(out *SudoRoleBindingGrant) {
	*out = *in
	out.Subject = in.Subject
	if in.Expiry != nil {
		in, out := &in.Expiry, &out.Expiry
		*out = new(time.Time)
		(*in).DeepCopyInto(*out)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new SudoRoleBindingGrant.
func (in *SudoRoleBindingGrant) DeepCopy() *SudoRoleBindingGrant {
	if in == nil {
		return nil
	}
	out := new(SudoRoleBindingGrant)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *SudoRoleBindingList) DeepCopyInto(out *SudoRoleBindingList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	out.ListMeta = in.ListMeta
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]SudoRoleBinding, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new SudoRoleBindingList.
func (in *SudoRoleBindingList) DeepCopy() *SudoRoleBindingList {
	if in == nil {
		return nil
	}
	out := new(SudoRoleBindingList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *SudoRoleBindingList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *SudoRoleBindingSpec) DeepCopyInto(out *SudoRoleBindingSpec) {
	*out = *in
	if in.Expiry != nil {
		in, out := &in.Expiry, &out.Expiry
		*out = new(int64)
		**out = **in
	}
	in.RoleBinding.DeepCopyInto(&out.RoleBinding)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new SudoRoleBindingSpec.
func (in *SudoRoleBindingSpec) DeepCopy() *SudoRoleBindingSpec {
	if in == nil {
		return nil
	}
	out := new(SudoRoleBindingSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *SudoRoleBindingStatus) DeepCopyInto(out *SudoRoleBindingStatus) {
	*out = *in
	if in.Grants != nil {
		in, out := &in.Grants, &out.Grants
		*out = make([]SudoRoleBindingGrant, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new SudoRoleBindingStatus.
func (in *SudoRoleBindingStatus) DeepCopy() *SudoRoleBindingStatus {
	if in == nil {
		return nil
	}
	out := new(SudoRoleBindingStatus)
	in.DeepCopyInto(out)
	return out
}
