/*
Copyright 2026 The Kubernetes Authors.

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

package e2e

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/kubernetes/test/e2e/framework"
)

const (
	// ccmDaemonSetName is the name of the CCM DaemonSet in kube-system namespace.
	ccmDaemonSetName = "aws-cloud-controller-manager"
	// ccmNamespace is the namespace where CCM daemonset is deployed by kops.
	ccmNamespace = "kube-system"
	// ccmLabelSelector is the label selector to identify CCM pods.
	ccmLabelSelector = "k8s-app=aws-cloud-controller-manager"
	// tempConfigMapName is the name used for the injected config map with the modified cloud config.
	tempConfigMapName = "aws-cloud-config-e2e"
	// defaultRestartTimeout is the default timeout for waiting for CCM pods to restart and become ready after config changes.
	defaultRestartTimeout = 3 * time.Minute
	// pollInterval is the interval for polling pod readiness after CCM restart.
	pollInterval = 5 * time.Second
)

// cloudConfigManager helps to change the CCM cloud configuration for e2e tests.
// It is engineered to work with kops-provisioned clusters that run CI tests.
// It modifies the CCM cloud config at runtime by creating a temporary ConfigMap and
// patching the DaemonSet to use it instead of the original hostPath volume.
type cloudConfigManager struct {
	// State tracking for restoration
	originalVolume      *v1.Volume
	originalVolumeMount *v1.VolumeMount
	configMapKey        string

	// restartTimeout defines for how long to wait for CCM pods to become ready
	// after configuration changes.
	restartTimeout time.Duration
}

// cloudConfigManagerOption is a functional option for configuring ccmCloudConfigManager.
type cloudConfigManagerOption func(*cloudConfigManager)

// withRestartTimeout sets the timeout for waiting for CCM pods to become ready after configuration changes.
func withRestartTimeout(timeout time.Duration) cloudConfigManagerOption {
	return func(m *cloudConfigManager) {
		m.restartTimeout = timeout
	}
}

// newCloudConfigManager creates a new CCM cloud config manager with the provided options.
func newCloudConfigManager(opts ...cloudConfigManagerOption) *cloudConfigManager {
	m := &cloudConfigManager{
		restartTimeout: defaultRestartTimeout,
	}

	// Apply options
	for _, opt := range opts {
		opt(m)
	}

	return m
}

// setCloudConfig modifies the CCM cloud configuration with the provided content, storing the original
// configuration state for later restoration.
//
// Steps:
//   - Finds the cloud-config path from CCM args
//   - Creates a temporary ConfigMap with the desired config
//   - Patches the CCM DaemonSet to use the ConfigMap instead of hostPath
//   - Adds subPath to volumeMount to mount ConfigMap key as a file
//   - Restarts CCM pods and waits for them to become ready
//
// Parameters:
//   - ctx: Context for the operation
//   - cs: Kubernetes clientset
//   - configContent: The cloud config file content to set.
//
// Returns error if any step fails or if CCM is not using hostPath.
func (m *cloudConfigManager) setCloudConfig(ctx context.Context, cs clientset.Interface, configContent string) error {
	framework.Logf("=== Setting CCM cloud configuration ===")

	// Get CCM DaemonSet
	ds, err := cs.AppsV1().DaemonSets(ccmNamespace).Get(ctx, ccmDaemonSetName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("failed to get CCM DaemonSet: %w", err)
	}

	// Find cloud-config file path from CCM container args
	if len(ds.Spec.Template.Spec.Containers) == 0 {
		return fmt.Errorf("CCM DaemonSet has no containers")
	}
	cloudConfigPath := getCloudConfigPath(ds.Spec.Template.Spec.Containers[0])

	// Check if CCM actually uses a cloud config. If not, return an error as it's an unsupported scenario.
	if cloudConfigPath == "" {
		return fmt.Errorf("CCM does not use --cloud-config flag")
	}
	framework.Logf("Cloud config path from CCM args: %s", cloudConfigPath)

	// Find the volume and volumeMount for cloud config
	_, volumeIdx, err := m.findCloudConfigVolume(ds, cloudConfigPath)
	if err != nil {
		return err
	}

	// Verify it's hostPath-based
	if m.originalVolume.HostPath == nil {
		return fmt.Errorf("CCM cloud config is not hostPath-based (only hostPath configs are supported)")
	}
	framework.Logf("Current config mount: HostPath=%s", m.originalVolume.HostPath.Path)

	// Create ConfigMap and patch DaemonSet. This also stores a copy of the original volume for later restoration.
	if err := m.createConfigMapAndPatchDaemonSet(ctx, cs, ds, volumeIdx, configContent); err != nil {
		return err
	}

	// Restart CCM pods and wait for them to be ready
	return restartCCMPods(ctx, cs, m.restartTimeout)
}

// restoreCloudConfig restores the original CCM cloud configuration as saved by setCloudConfig.
// This restores the hostPath volume created by kops and deletes the temporary ConfigMap injected.
func (m *cloudConfigManager) restoreCloudConfig(ctx context.Context, cs clientset.Interface) error {
	framework.Logf("=== Restoring original CCM configuration ===")

	ds, err := cs.AppsV1().DaemonSets(ccmNamespace).Get(ctx, ccmDaemonSetName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("failed to get DaemonSet: %w", err)
	}

	if m.originalVolume == nil {
		return fmt.Errorf("no original volume to restore")
	}

	// Restore original volume
	for i, vol := range ds.Spec.Template.Spec.Volumes {
		if vol.Name == m.originalVolume.Name {
			ds.Spec.Template.Spec.Volumes[i] = *m.originalVolume
			framework.Logf("Restored original volume: %s", m.originalVolume.Name)
			break
		}
	}

	// Restore original volumeMount (remove subPath)
	if m.originalVolumeMount != nil {
		for i, container := range ds.Spec.Template.Spec.Containers {
			for j, mount := range container.VolumeMounts {
				if mount.Name == m.originalVolume.Name {
					ds.Spec.Template.Spec.Containers[i].VolumeMounts[j] = *m.originalVolumeMount
					framework.Logf("Restored original volumeMount")
					break
				}
			}
		}
	}

	// Update DaemonSet
	_, err = cs.AppsV1().DaemonSets(ccmNamespace).Update(ctx, ds, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("failed to restore DaemonSet: %w", err)
	}
	framework.Logf("Restored DaemonSet to use hostPath")

	// Delete temporary ConfigMap
	err = cs.CoreV1().ConfigMaps(ccmNamespace).Delete(ctx, tempConfigMapName, metav1.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("failed to delete ConfigMap: %w", err)
	}
	framework.Logf("Deleted temporary ConfigMap %s", tempConfigMapName)

	// Restart CCM pods to load original config
	return restartCCMPods(ctx, cs, m.restartTimeout)
}

// getCloudConfigPath extracts the cloud config path from CCM container arguments.
// Returns empty string if --cloud-config flag is not found.
func getCloudConfigPath(container v1.Container) string {
	for i, arg := range container.Args {
		if arg == "--cloud-config" && i+1 < len(container.Args) {
			return container.Args[i+1]
		} else if strings.HasPrefix(arg, "--cloud-config=") {
			return strings.TrimPrefix(arg, "--cloud-config=")
		}
	}

	return "" // No cloud-config flag found
}

// findCloudConfigVolume locates the volume and volumeMount for the cloud config in the CCM DaemonSet.
// It returns the volume name, volume index, and ConfigMap key.
func (m *cloudConfigManager) findCloudConfigVolume(ds *appsv1.DaemonSet, cloudConfigPath string) (volumeName string, volumeIdx int, err error) {
	if len(ds.Spec.Template.Spec.Containers) == 0 {
		return "", -1, fmt.Errorf("CCM DaemonSet has no containers")
	}
	container := ds.Spec.Template.Spec.Containers[0]

	// Find volumeMount that matches the cloud config path
	for _, mount := range container.VolumeMounts {
		if mount.MountPath == cloudConfigPath {
			volumeName = mount.Name
			// If SubPath is set, that's the ConfigMap key; otherwise use basename of path
			if mount.SubPath != "" {
				m.configMapKey = mount.SubPath
			} else {
				m.configMapKey = filepath.Base(cloudConfigPath)
			}
			framework.Logf("Found cloud config volumeMount: name=%s, mountPath=%s, subPath=%s, key=%s",
				volumeName, mount.MountPath, mount.SubPath, m.configMapKey)
			break
		}
	}
	if volumeName == "" {
		return "", -1, fmt.Errorf("cloud config volumeMount not found for path %s", cloudConfigPath)
	}

	// Find the volume by name
	for i, vol := range ds.Spec.Template.Spec.Volumes {
		if vol.Name == volumeName {
			volumeIdx = i
			m.originalVolume = vol.DeepCopy()
			framework.Logf("Found cloud config volume: name=%s, type=%s", vol.Name, getVolumeType(vol))
			return volumeName, volumeIdx, nil
		}
	}

	return "", -1, fmt.Errorf("cloud config volume not found for name %s", volumeName)
}

// createConfigMapAndPatchDaemonSet creates a new ConfigMap with cloud config and patches
// the CCM DaemonSet to use it instead of hostPath.
func (m *cloudConfigManager) createConfigMapAndPatchDaemonSet(ctx context.Context, cs clientset.Interface, ds *appsv1.DaemonSet, volumeIdx int, configContent string) error {
	framework.Logf("Creating temporary ConfigMap and patching DaemonSet")

	// Create ConfigMap with the detected key
	cm := &v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      tempConfigMapName,
			Namespace: ccmNamespace,
		},
		Data: map[string]string{
			m.configMapKey: configContent,
		},
	}
	_, err := cs.CoreV1().ConfigMaps(ccmNamespace).Create(ctx, cm, metav1.CreateOptions{})
	if err != nil {
		if apierrors.IsAlreadyExists(err) {
			// ConfigMap already exists, update it
			framework.Logf("ConfigMap %s already exists, updating...", tempConfigMapName)
			_, err = cs.CoreV1().ConfigMaps(ccmNamespace).Update(ctx, cm, metav1.UpdateOptions{})
			if err != nil {
				return fmt.Errorf("failed to update existing ConfigMap: %w", err)
			}
			framework.Logf("Updated ConfigMap %s with key '%s'", tempConfigMapName, m.configMapKey)
		} else {
			return fmt.Errorf("failed to create ConfigMap: %w", err)
		}
	} else {
		framework.Logf("Created ConfigMap %s with key '%s'", tempConfigMapName, m.configMapKey)
	}

	// Patch DaemonSet volume to use ConfigMap
	ds.Spec.Template.Spec.Volumes[volumeIdx] = v1.Volume{
		Name: m.originalVolume.Name,
		VolumeSource: v1.VolumeSource{
			ConfigMap: &v1.ConfigMapVolumeSource{
				LocalObjectReference: v1.LocalObjectReference{
					Name: tempConfigMapName,
				},
			},
		},
	}

	// Find and patch volumeMount to use subPath
	// ConfigMap mounts as directory, hostPath as file
	// Without subPath, /etc/kubernetes/cloud.config becomes a directory
	for i, container := range ds.Spec.Template.Spec.Containers {
		for j, mount := range container.VolumeMounts {
			if mount.Name == m.originalVolume.Name {
				// Save original volumeMount for rollback
				m.originalVolumeMount = mount.DeepCopy()
				// Add subPath to mount ConfigMap key as file
				ds.Spec.Template.Spec.Containers[i].VolumeMounts[j].SubPath = m.configMapKey
				framework.Logf("Added subPath=%s to volumeMount", m.configMapKey)
				break
			}
		}
	}

	_, err = cs.AppsV1().DaemonSets(ccmNamespace).Update(ctx, ds, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("failed to update DaemonSet: %w", err)
	}
	framework.Logf("Patched DaemonSet to use ConfigMap")

	return nil
}

// restartCCMPods restarts all CCM pods and waits for them to become ready.
func restartCCMPods(ctx context.Context, cs clientset.Interface, timeout time.Duration) error {
	framework.Logf("Restarting CCM pods")

	ccmPods, err := cs.CoreV1().Pods(ccmNamespace).List(ctx, metav1.ListOptions{
		LabelSelector: ccmLabelSelector,
	})
	if err != nil {
		return fmt.Errorf("failed to list CCM pods: %w", err)
	}

	for _, pod := range ccmPods.Items {
		err = cs.CoreV1().Pods(ccmNamespace).Delete(ctx, pod.Name, metav1.DeleteOptions{})
		// Ignore NotFound errors - pod may already be deleting due to DaemonSet update
		if err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("failed to delete pod %s: %w", pod.Name, err)
		}
	}

	// Wait for new pods to be Running AND Ready
	framework.Logf("Waiting for CCM pods to become ready (timeout: %v)", timeout)
	err = wait.PollUntilContextTimeout(ctx, pollInterval, timeout, true, func(ctx context.Context) (bool, error) {
		pods, err := cs.CoreV1().Pods(ccmNamespace).List(ctx, metav1.ListOptions{
			LabelSelector: ccmLabelSelector,
		})
		if err != nil || len(pods.Items) == 0 {
			return false, nil
		}
		for _, pod := range pods.Items {
			if pod.Status.Phase != v1.PodRunning {
				return false, nil
			}
			// Check container ready status
			ready := false
			for _, condition := range pod.Status.Conditions {
				if condition.Type == v1.PodReady && condition.Status == v1.ConditionTrue {
					ready = true
					break
				}
			}
			if !ready {
				return false, nil
			}
		}
		return true, nil
	})
	if err != nil {
		return fmt.Errorf("CCM pods did not become ready within %v: %w", timeout, err)
	}
	framework.Logf("CCM restarted successfully")

	return nil
}

// getVolumeType returns a string describing the type of volume.
func getVolumeType(vol v1.Volume) string {
	if vol.ConfigMap != nil {
		return "ConfigMap"
	} else if vol.HostPath != nil {
		return "HostPath"
	}
	return "Unknown"
}
