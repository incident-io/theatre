# Theatre

This project contains GoCardless' Kubernetes extensions, in the form of
operators, admission controller webhooks and associated CLIs. The aim of this
project is to provide a space to write Kubernetes extensions where:

1. Doing the right thing is easy; it is difficult to make mistakes!
2. Each category of Kubernetes extension has a well defined implementation pattern
3. Writing meaningful tests is easy, with minimal boilerplate

## API Groups

Theatre provides various extensions to vanilla Kubernetes. These extensions are
grouped under separate API groups, all of which exist under the
`*.crd.gocardless.com` namespace.

### RBAC

Utilities to extend the default Kubernetes role-based access control (RBAC)
resources.
These CRDs are motivated by real-world use cases when using
Kubernetes with an organisation that uses GSuite, and which frequently onboards
new developers.

- [`DirectoryRoleBinding`][sample-drb] is a resource that provisions standard
  `RoleBinding`s, which contain the subjects defined in a  Google group.

> Note: In a GKE Kubernetes cluster this may soon be superseded by the [Google
> Groups for GKE][gke-groups] functionality.

- [`PAMRoleBinding`][sample-prb] gives a role in its namespace to everyone holding an
  active grant on a Google Cloud [Privileged Access Manager][pam] (PAM) entitlement, for
  just-in-time access. See [PAMRoleBinding](#pamrolebinding) below.

[sample-drb]: config/samples/rbac_v1alpha1_directoryrolebinding.yaml
[sample-prb]: config/samples/rbac_v1alpha1_pamrolebinding.yaml
[pam]: https://cloud.google.com/iam/docs/pam-overview
[gke-groups]: https://cloud.google.com/kubernetes-engine/docs/how-to/role-based-access-control#google-groups-for-gke

#### PAMRoleBinding

PAM already handles requesting access, approving it, expiring it and auditing it. A
`PAMRoleBinding` turns an active grant into Kubernetes RBAC, so the access applies on the
user's next request, with no new login and no group membership to propagate.

```yaml
apiVersion: rbac.crd.gocardless.com/v1alpha1
kind: PAMRoleBinding
metadata:
  name: operator
  namespace: my-app
spec:
  entitlement: projects/my-project/locations/global/entitlements/my-app-operator
  roleRef:
    apiGroup: rbac.authorization.k8s.io
    kind: ClusterRole
    name: my-operator-role
```

To give one entitlement access in several namespaces, create a `PAMRoleBinding` in each.

Every `--pam-refresh` (10s by default), rbac-manager lists the entitlement's active
grants and keeps one `RoleBinding` per grant in the `PAMRoleBinding`'s namespace, for the
requester's email. Only people are bound: a requester must be a bare email or a `user:` principal.
Service accounts, groups and federated principals are skipped, with a `GrantSkipped`
warning event. Bindings are named
`pam-<PAMRoleBinding name>-<local part of their email>-<hash of the grant>`, e.g.
`pam-operator-jane-doe-1a2b3c4d`. Each binding is
owned by the `PAMRoleBinding` and annotated with the grant
(`pam.rbac.crd.gocardless.com/grant`, `grant-id`), its `requester`, its `approvers`
(comma-separated, as PAM supports several approval levels), and when it ends
(`ends-at`). A finalizer deletes the bindings with the `PAMRoleBinding`, even if
it's deleted with `--cascade=orphan`.

- A binding is deleted when its grant ends, is withdrawn or is revoked, and at `ends-at`
  even if PAM can't be reached. A failed call to
  PAM never removes access early.
- `status` lists the bound grants (subject, approvers, end time) and when PAM was last
  listed. The `Ready` condition reports `EntitlementNotFound` (usually a typo in `spec.entitlement`),
  `EntitlementNotAllowed`, `PAMUnreachable` or `RoleBindingFailed`, and events record
  each grant bound, expired or withdrawn.
- Metrics, labelled by the PAMRoleBinding's `namespace` and `name`:
  `theatre_rbac_pamrolebinding_last_sync_timestamp_seconds`,
  `theatre_rbac_pamrolebinding_entitlement_not_found` and
  `theatre_rbac_pamrolebinding_active_grants`. Alert on the first, so you hear if
  grants stop turning into access, or access stops being removed.

The entitlement must grant some IAM role for PAM to create grants. Pick one the
eligible users already hold, so the grant adds nothing in IAM.

To run it, start rbac-manager with `--pam`. It only honours entitlements in the Google
Cloud project it runs in, which it reads from the metadata server at startup, and won't
start if it can't. Other entitlements are refused with `EntitlementNotAllowed`. It uses
Application Default Credentials, which need `privilegedaccessmanager.grants.list` on
that project (e.g. `roles/privilegedaccessmanager.viewer`, through Workload Identity on
GKE). `spec.entitlement` is immutable: to point a binding at another entitlement,
recreate it.

**Lock it down.** rbac-manager creates the bindings, so Kubernetes' usual check that you
may grant a role you bind is made against rbac-manager, not against whoever wrote the
`PAMRoleBinding`. Limiting entitlements to rbac-manager's own project stops anyone who
can create one pointing it at an entitlement in a project they control. Also:

- give rbac-manager's ClusterRole `bind` only on the roles you intend to hand out
  (`resourceNames`), plus `create`, `delete`, `get`, `list` and `watch` on `rolebindings`,
  and `update` on `pamrolebindings`, `pamrolebindings/status` and
  `pamrolebindings/finalizers`. It never updates a `RoleBinding`;
- restrict who can create `PAMRoleBinding`s, and consider an admission policy that
  allowlists their `roleRef`s.

If you don't use `DirectoryRoleBinding`, pass `--no-directory-role-binding`, which
removes rbac-manager's need to update `RoleBinding`s.

### Workloads

Extends core workload resources with new CRDs. Extensions within this group can be
expected to create or mutate pods, deployments, etc.

- [Consoles](controllers/workloads/console/README.md): Provide engineers with a temporary
  dedicated pod to perform operational tasks, avoiding the need to provide
  `pods/exec` permissions on production workloads.

### [Vault](apis/vault/v1alpha1/README.md)

Utilities for interacting with Vault. Primarily used to inject secret material
into pods by use of annotations.

- `secrets-injector.vault.crd.gocardless.com` webhook for injecting the
  `theatre-secrets` tool to populate a container's environment with secrets
  from Vault before executing.

## Command line interfaces

As well as Kubernetes controllers this project also contains supporting CLI
utilities.

### theatre-consoles

`theatre-consoles` is a suite of commands that provides the ability to create,
list, attach to and authorise [consoles](#workloads).

Run: `go run cmd/theatre-consoles/main.go`

### theatre-secrets

See the [command README](cmd/theatre-secrets/README.md) for further details.

Run: `go run cmd/theatre-secrets/main.go`

## Getting Started

Theatre assumes developers have several tools installed to provide development
and testing capabilities. The following will configure a macOS environment with
all the necessary dependencies:


```shell
make install-tools-homebrew
make install-tools-kubebuilder
make install-tools
sudo mkdir /usr/local/kubebuilder
curl -fsL "https://github.com/kubernetes-sigs/kubebuilder/releases/download/v2.3.1/kubebuilder_2.3.1_$(go env GOOS)_$(go env GOARCH).tar.gz" | \
  sudo tar -xvz --strip=1 -C /usr/local/kubebuilder
export KUBEBUILDER_ASSETS=/usr/local/kubebuilder/bin
```

## Local development environment

For developing changes, you can make use of the acceptance testing
infrastructure to install the code into a local Kubernetes-in-Docker
([Kind][kind]) cluster.
Ensure `kind` is installed (as per the [getting started
steps][#getting-started]) and then run the following:

```shell
make build
make test
make acceptance-e2e
```

You can also run the individual commands, check the Makefile for more details,

Example: get the kind cluster read for the acceptance tests

```shell
go run cmd/acceptance/main.go prepare # prepare the cluster, install theatre
```

At this point a development cluster has been provisioned. Your current local
Kubernetes context will have been changed to point to the test cluster. You
should see the following if you inspect kubernetes:

```console
$ kubectl get pods --all-namespaces | grep -v kube-system
NAMESPACE        NAME                                        READY   STATUS    RESTARTS   AGE
theatre-system   theatre-rbac-manager-0                      1/1     Running   0          5m
theatre-system   theatre-vault-manager-0                     1/1     Running   0          5m
theatre-system   theatre-workloads-manager-0                 1/1     Running   0          5m
vault            vault-0                                     1/1     Running   0          5m
```

All of the controllers and webhooks, built from the local working copy of the
code, have been installed into the cluster.

As this is a fully-fledged Kubernetes cluster, at this point you are able to
interact with it as you would with any other cluster, but also have the ability
to use the custom resources defined in theatre, e.g. creating a `Console`.

If changes are made to the code, then you must re-run the `prepare` step in
order to update the cluster with images built from the new binaries.

[kind]: https://github.com/kubernetes-sigs/kind

## Tests

Theatre has test suites at several different levels, each of which play a
specific role. All of these suites are written using the [Ginkgo][ginkgo]
framework.

In order to setup your local testing environment for unit and integration tests do the following:

```shell
$ make install-tools
$ # install setup-envtest which configures etcd and kube-apiserver binaries for envtest
$ # https://book.kubebuilder.io/reference/envtest.html#configuring-envtest-for-integration-tests
$ # https://github.com/kubernetes-sigs/controller-runtime/tree/master/tools/setup-envtest#envtest-binaries-manager
$ # Configures envtest to use k8s 1.24.x binaries, in your shell (if required)
$ eval $(setup-envtest use -i -p env 1.24.x)
```

- **Unit**: Standard unit tests, used to exhaustively specify the functionality of
  functions or objects.

  Invoked with the `ginkgo` CLI. (requires setup-envtest variable)

```
make test
```

  [Example unit test](apis/workloads/v1alpha1/helpers_test.go).

- **Integration**: Integration tests run the custom controller code and
  integrates this with a temporary Kubernetes API server, therefore providing an
  environment where the Kubernetes API can be used to manipulate custom objects.

  This environment has no Kubernetes nodes, and does not run any other
  controllers such as `kube-controller-manager`, therefore it will not run pods.

  These suites provide a good balance between runtime and realism, and are
  therefore useful for rapid iteration when developing changes.

  Invoked with the `ginkgo` CLI.

  [Example integration test](apis/workloads/v1alpha1/integration/priority_integration_test.go).

- **Acceptance**: Acceptance is used for full end-to-end (E2E) tests,
  provisioning a fully functional Kubernetes cluster with all custom controllers
  and webhooks installed.

  The acceptance tests are much slower to set up, and so are typically used
  sparingly compared to the other suites, but provide essential validation in CI
  and at the end of development cycles that the code correctly interacts with
  the other components of a Kubernetes cluster.

  Invoked with: `make acceptance-run`

  [Example acceptance test](cmd/workloads-manager/acceptance/acceptance.go).

[ginkgo]: https://onsi.github.io/ginkgo


## Upgrading theatre

### Upgrading from v4 to v5

Theatre v5 is using the Kubebuilder v3 with its new layout, which introduces the
following changes:
#### Go module is now upgraded from github.com/gocardless/theatre/v4 to github.com/gocardless/theatre/v5
The go module is now upgraded from github.com/gocardless/theatre/v4 to github.com/gocardless/theatre/v5, including all code references.


#### `apis` folder is now called `api`
Meaning that if you are importing any packages from `github.com/gocardless/theatre/v4/apis`, they should now be imported from `github.com/gocardless/theatre/v5/api`.

#### `internal` folder has been added
The unexported internal folder has been added to the project layout, containing the controllers and webhooks. If you were previously importing the controllers or webhooks you won't be able to do so any more.

#### `pkg` folder
No changes here, any packages imported from the `github.com/gocardless/theatre/v4/pkg` should continue to work as expected in v5 by using `github.com/gocardless/theatre/v5/pkg`.

#### CRDs have to be imported manually from `config/crd`
The CRDs are no longer included in the `config/base` kustomization and have to be imported manually from `config/crd`.

```yaml
# Before
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - github.com/gocardless/theatre/config/base?ref=v4.x.x

# After
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - github.com/gocardless/theatre/config/crd?ref=v5.x.x
  - github.com/gocardless/theatre/config/base?ref=v5.x.x
```