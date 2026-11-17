package pamrolebinding

import (
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

var (
	labels = []string{"namespace", "name"}

	lastSyncTimestamp = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "theatre_rbac_pamrolebinding_last_sync_timestamp_seconds",
		Help: "Unix time at which the PAMRoleBinding's active grants were last listed from PAM successfully.",
	}, labels)
	entitlementNotFound = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "theatre_rbac_pamrolebinding_entitlement_not_found",
		Help: "1 if PAM reported that the PAMRoleBinding's entitlement does not exist, otherwise 0.",
	}, labels)
	activeGrants = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "theatre_rbac_pamrolebinding_active_grants",
		Help: "Number of users the PAMRoleBinding currently binds.",
	}, labels)
)

func init() {
	metrics.Registry.MustRegister(lastSyncTimestamp, entitlementNotFound, activeGrants)
}

func forgetMetrics(namespace, name string) {
	for _, m := range []*prometheus.GaugeVec{lastSyncTimestamp, entitlementNotFound, activeGrants} {
		m.DeleteLabelValues(namespace, name)
	}
}
