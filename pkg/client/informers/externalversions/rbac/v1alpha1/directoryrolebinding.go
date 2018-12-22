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

// Code generated by informer-gen. DO NOT EDIT.

package v1alpha1

import (
	time "time"

	rbacv1alpha1 "github.com/lawrencejones/theatre/pkg/apis/rbac/v1alpha1"
	versioned "github.com/lawrencejones/theatre/pkg/client/clientset/versioned"
	internalinterfaces "github.com/lawrencejones/theatre/pkg/client/informers/externalversions/internalinterfaces"
	v1alpha1 "github.com/lawrencejones/theatre/pkg/client/listers/rbac/v1alpha1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	watch "k8s.io/apimachinery/pkg/watch"
	cache "k8s.io/client-go/tools/cache"
)

// DirectoryRoleBindingInformer provides access to a shared informer and lister for
// DirectoryRoleBindings.
type DirectoryRoleBindingInformer interface {
	Informer() cache.SharedIndexInformer
	Lister() v1alpha1.DirectoryRoleBindingLister
}

type directoryRoleBindingInformer struct {
	factory          internalinterfaces.SharedInformerFactory
	tweakListOptions internalinterfaces.TweakListOptionsFunc
	namespace        string
}

// NewDirectoryRoleBindingInformer constructs a new informer for DirectoryRoleBinding type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewDirectoryRoleBindingInformer(client versioned.Interface, namespace string, resyncPeriod time.Duration, indexers cache.Indexers) cache.SharedIndexInformer {
	return NewFilteredDirectoryRoleBindingInformer(client, namespace, resyncPeriod, indexers, nil)
}

// NewFilteredDirectoryRoleBindingInformer constructs a new informer for DirectoryRoleBinding type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewFilteredDirectoryRoleBindingInformer(client versioned.Interface, namespace string, resyncPeriod time.Duration, indexers cache.Indexers, tweakListOptions internalinterfaces.TweakListOptionsFunc) cache.SharedIndexInformer {
	return cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options v1.ListOptions) (runtime.Object, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.RbacV1alpha1().DirectoryRoleBindings(namespace).List(options)
			},
			WatchFunc: func(options v1.ListOptions) (watch.Interface, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.RbacV1alpha1().DirectoryRoleBindings(namespace).Watch(options)
			},
		},
		&rbacv1alpha1.DirectoryRoleBinding{},
		resyncPeriod,
		indexers,
	)
}

func (f *directoryRoleBindingInformer) defaultInformer(client versioned.Interface, resyncPeriod time.Duration) cache.SharedIndexInformer {
	return NewFilteredDirectoryRoleBindingInformer(client, f.namespace, resyncPeriod, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc}, f.tweakListOptions)
}

func (f *directoryRoleBindingInformer) Informer() cache.SharedIndexInformer {
	return f.factory.InformerFor(&rbacv1alpha1.DirectoryRoleBinding{}, f.defaultInformer)
}

func (f *directoryRoleBindingInformer) Lister() v1alpha1.DirectoryRoleBindingLister {
	return v1alpha1.NewDirectoryRoleBindingLister(f.Informer().GetIndexer())
}
