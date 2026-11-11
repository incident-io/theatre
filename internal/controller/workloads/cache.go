package controllers

import (
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ConsoleNameLabel is set on every Job the console controller creates, and on
// the pods those Jobs run.
const ConsoleNameLabel = "console-name"

// CacheOptions limits the manager's Job and Pod informers to objects that
// belong to a console. Without this the manager caches every Job and Pod in
// the cluster, so its memory grows with workloads it never reads.
//
// Reads of a Job or Pod without the label through the cached client return
// NotFound. Use the manager's API reader for anything else.
func CacheOptions() cache.Options {
	consoleOwned := consoleOwnedSelector()
	return cache.Options{
		ByObject: map[client.Object]cache.ByObject{
			&batchv1.Job{}: {Label: consoleOwned},
			&corev1.Pod{}:  {Label: consoleOwned},
		},
	}
}

func consoleOwnedSelector() labels.Selector {
	req, err := labels.NewRequirement(ConsoleNameLabel, selection.Exists, nil)
	if err != nil {
		panic(err) // the key is a constant, so this cannot fail
	}
	return labels.NewSelector().Add(*req)
}
