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

// Code generated by client-gen. DO NOT EDIT.

package v1alpha1

import (
	v1alpha1 "github.com/gocardless/theatre/pkg/apis/workloads/v1alpha1"
	scheme "github.com/gocardless/theatre/pkg/client/clientset/versioned/scheme"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	rest "k8s.io/client-go/rest"
)

// ConsolesGetter has a method to return a ConsoleInterface.
// A group's client should implement this interface.
type ConsolesGetter interface {
	Consoles(namespace string) ConsoleInterface
}

// ConsoleInterface has methods to work with Console resources.
type ConsoleInterface interface {
	Create(*v1alpha1.Console) (*v1alpha1.Console, error)
	Update(*v1alpha1.Console) (*v1alpha1.Console, error)
	UpdateStatus(*v1alpha1.Console) (*v1alpha1.Console, error)
	Delete(name string, options *v1.DeleteOptions) error
	DeleteCollection(options *v1.DeleteOptions, listOptions v1.ListOptions) error
	Get(name string, options v1.GetOptions) (*v1alpha1.Console, error)
	List(opts v1.ListOptions) (*v1alpha1.ConsoleList, error)
	Watch(opts v1.ListOptions) (watch.Interface, error)
	Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *v1alpha1.Console, err error)
	ConsoleExpansion
}

// consoles implements ConsoleInterface
type consoles struct {
	client rest.Interface
	ns     string
}

// newConsoles returns a Consoles
func newConsoles(c *WorkloadsV1alpha1Client, namespace string) *consoles {
	return &consoles{
		client: c.RESTClient(),
		ns:     namespace,
	}
}

// Get takes name of the console, and returns the corresponding console object, and an error if there is any.
func (c *consoles) Get(name string, options v1.GetOptions) (result *v1alpha1.Console, err error) {
	result = &v1alpha1.Console{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource("consoles").
		Name(name).
		VersionedParams(&options, scheme.ParameterCodec).
		Do().
		Into(result)
	return
}

// List takes label and field selectors, and returns the list of Consoles that match those selectors.
func (c *consoles) List(opts v1.ListOptions) (result *v1alpha1.ConsoleList, err error) {
	result = &v1alpha1.ConsoleList{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource("consoles").
		VersionedParams(&opts, scheme.ParameterCodec).
		Do().
		Into(result)
	return
}

// Watch returns a watch.Interface that watches the requested consoles.
func (c *consoles) Watch(opts v1.ListOptions) (watch.Interface, error) {
	opts.Watch = true
	return c.client.Get().
		Namespace(c.ns).
		Resource("consoles").
		VersionedParams(&opts, scheme.ParameterCodec).
		Watch()
}

// Create takes the representation of a console and creates it.  Returns the server's representation of the console, and an error, if there is any.
func (c *consoles) Create(console *v1alpha1.Console) (result *v1alpha1.Console, err error) {
	result = &v1alpha1.Console{}
	err = c.client.Post().
		Namespace(c.ns).
		Resource("consoles").
		Body(console).
		Do().
		Into(result)
	return
}

// Update takes the representation of a console and updates it. Returns the server's representation of the console, and an error, if there is any.
func (c *consoles) Update(console *v1alpha1.Console) (result *v1alpha1.Console, err error) {
	result = &v1alpha1.Console{}
	err = c.client.Put().
		Namespace(c.ns).
		Resource("consoles").
		Name(console.Name).
		Body(console).
		Do().
		Into(result)
	return
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().

func (c *consoles) UpdateStatus(console *v1alpha1.Console) (result *v1alpha1.Console, err error) {
	result = &v1alpha1.Console{}
	err = c.client.Put().
		Namespace(c.ns).
		Resource("consoles").
		Name(console.Name).
		SubResource("status").
		Body(console).
		Do().
		Into(result)
	return
}

// Delete takes name of the console and deletes it. Returns an error if one occurs.
func (c *consoles) Delete(name string, options *v1.DeleteOptions) error {
	return c.client.Delete().
		Namespace(c.ns).
		Resource("consoles").
		Name(name).
		Body(options).
		Do().
		Error()
}

// DeleteCollection deletes a collection of objects.
func (c *consoles) DeleteCollection(options *v1.DeleteOptions, listOptions v1.ListOptions) error {
	return c.client.Delete().
		Namespace(c.ns).
		Resource("consoles").
		VersionedParams(&listOptions, scheme.ParameterCodec).
		Body(options).
		Do().
		Error()
}

// Patch applies the patch and returns the patched console.
func (c *consoles) Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *v1alpha1.Console, err error) {
	result = &v1alpha1.Console{}
	err = c.client.Patch(pt).
		Namespace(c.ns).
		Resource("consoles").
		SubResource(subresources...).
		Name(name).
		Body(data).
		Do().
		Into(result)
	return
}
