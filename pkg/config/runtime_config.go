package config

import "time"

// RuntimeConfig stores the configuration for controller-runtime
type RuntimeConfig struct {
	MetricsBindAddress           string
	HealthProbeBindAddress       string
	LeaderElect                  bool
	LeaderElectLeaseDuration     time.Duration
	LeaderElectRenewDeadline     time.Duration
	LeaderElectRetryPeriod       time.Duration
	LeaderElectResourceLock      string
	LeaderElectResourceName      string
	LeaderElectResourceNamespace string
	SyncPeriod                   time.Duration
	QPS                          float32
	Burst                        int
}
