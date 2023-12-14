// Copyright Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package nodeagent

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"istio.io/istio/cni/pkg/iptables"
	"istio.io/istio/cni/pkg/util"
	istiolog "istio.io/istio/pkg/log"
	"istio.io/istio/pkg/util/sets"
	dep "istio.io/istio/tools/istio-iptables/pkg/dependencies"
)

var log = istiolog.RegisterScope("ambient", "ambient controller")

// Adapts CNI to ztunnel server. decoupled from k8s for easier integration testing.
type NetServer struct {
	ztunnelServer        ZtunnelServer
	currentPodSnapshot   *podNetnsCache
	iptablesConfigurator *iptables.IptablesConfigurator
	podNs                PodNetnsFinder
	// allow overriding for tests
	netnsRunner func(fdable NetnsFd, toRun func() error) error
}

var _ MeshDataplane = &NetServer{}

func newNetServer(ztunnelServer ZtunnelServer, podNsMap *podNetnsCache,
	iptablesConfigurator *iptables.IptablesConfigurator, podNs PodNetnsFinder,
) *NetServer {
	return &NetServer{
		ztunnelServer:        ztunnelServer,
		currentPodSnapshot:   podNsMap,
		podNs:                podNs,
		iptablesConfigurator: iptablesConfigurator,
		netnsRunner:          NetnsDo,
	}
}

func (s *NetServer) Start(ctx context.Context) {
	log.Debug("starting ztunnel server")
	go s.ztunnelServer.Run(ctx)
}

func (s *NetServer) Stop() {
	log.Debug("removing host iptables rules")
	s.iptablesConfigurator.DeleteHostRules()

	log.Debug("stopping ztunnel server")
	s.ztunnelServer.Close()
}

func (s *NetServer) rescanPod(pod *metav1.ObjectMeta) error {
	// if we get ErrPodNotFound, it means we got the pod, but no netns.
	// this can happen if the pod was dynamically added to the mesh after it was created.
	// in that case, try finding the netns using procfs.
	filter := sets.New[types.UID]()
	filter.Insert(pod.UID)
	return s.scanProcForPodsAndCache(filter)
}

func (s *NetServer) getOrOpenNetns(pod *metav1.ObjectMeta, netNs string) (Netns, error) {
	if netNs == "" {
		return s.getNetns(pod)
	}
	return s.openNetns(pod, netNs)
}

func (s *NetServer) openNetns(pod *metav1.ObjectMeta, netNs string) (Netns, error) {
	openNetns, err := s.currentPodSnapshot.UpsertPodCache(string(pod.UID), netNs)
	if !errors.Is(err, ErrPodNotFound) {
		return openNetns, err
	}
	// only rescan if the error is ErrPodNotFound
	log.Debug("pod netns was not found, trying to find it using procfs")
	// if we get ErrPodNotFound, it means we got the pod, but no netns.
	// this can happen if the pod was dynamically added to the mesh after it was created.
	// in that case, try finding the netns using procfs.
	if err := s.rescanPod(pod); err != nil {
		log.Errorf("error scanning proc: error was %s", err)
		return nil, err
	}
	// try again. we can still get here if the pod is in the process of being created.
	// in this case the CNI will be invoked soon and provide us with the netns.
	openNetns, err = s.currentPodSnapshot.UpsertPodCache(string(pod.UID), netNs)
	if err != nil && errors.Is(err, ErrPodNotFound) {
		return nil, fmt.Errorf("can't find netns for pod, this is ok if this is a newly created pod (%w)", err)
	}

	return openNetns, err
}

func (s *NetServer) getNetns(pod *metav1.ObjectMeta) (Netns, error) {
	openNetns := s.currentPodSnapshot.Get(string(pod.UID))
	if openNetns != nil {
		return openNetns, nil
	}
	// only rescan if the error is ErrPodNotFound
	log.Debug("pod netns was not found, trying to find it using procfs")
	// if we get ErrPodNotFound, it means we got the pod, but no netns.
	// this can happen if the pod was dynamically added to the mesh after it was created.
	// in that case, try finding the netns using procfs.
	if err := s.rescanPod(pod); err != nil {
		log.Errorf("error scanning proc: error was %s", err)
		return nil, err
	}
	// try again. we can still get here if the pod is in the process of being created.
	// in this case the CNI will be invoked soon and provide us with the netns.
	openNetns = s.currentPodSnapshot.Get(string(pod.UID))
	if openNetns == nil {
		return nil, fmt.Errorf("can't find netns for pod, this is ok if this is a newly created pod (%w)", ErrPodNotFound)
	}

	return openNetns, nil
}

// AddPodToMesh adds a pod to mesh by
// 1. Getting the netns
// 2. Adding the pod's IPs to the hostnetns ipsets for node probe checks
// 3. Creating iptables rules inside the pod's netns
// 4. Notifying ztunnel via GRPC to create a proxy for the pod
//
// You may ask why we pass the pod IPs separately from the pod manifest itself (which contains the pod IPs as a field)
// - this is because during add specifically, if CNI plugins have not finished executing,
// K8S may get a pod Add event without any IPs in the object, and the pod will later be updated with IPs.
//
// We always need the IPs, but this is fine because this AddPodToMesh can be called from the CNI plugin as well,
// which always has the firsthand info of the IPs, even before K8S does - so we pass them separately here because
// we actually may have them before K8S in the Pod object.
func (s *NetServer) AddPodToMesh(ctx context.Context, pod *corev1.Pod, podIPs []netip.Addr, netNs string) error {
	log.Info("in pod mode - adding pod to ztunnel")
	// make sure the cache is aware of the pod, even if we don't have the netns yet.
	s.currentPodSnapshot.Ensure(string(pod.UID))
	openNetns, err := s.getOrOpenNetns(&pod.ObjectMeta, netNs)
	if err != nil {
		return err
	}

	log.Debug("calling CreateInpodRules")
	if err := s.netnsRunner(openNetns, func() error {
		return s.iptablesConfigurator.CreateInpodRules(&HostProbeSNATIP)
	}); err != nil {
		log.Errorf("failed to update POD inpod: %s/%s %v", pod.Namespace, pod.Name, err)
		return err
	}

	log.Debug("notifying subscribed node proxies")
	if err := s.sendPodToZtunnelAndWaitForAck(ctx, &pod.ObjectMeta, openNetns); err != nil {
		// we must return PartialAdd error here. the pod was injected with iptables rules,
		// so it should be annotated, so if it is removed from the mesh, the rules will be removed.
		// alternatively, we may not return an error at all, but we want this to fail on tests.
		return NewErrPartialAdd(err)
	}
	return nil
}

func (s *NetServer) sendPodToZtunnelAndWaitForAck(ctx context.Context, pod *metav1.ObjectMeta, netns Netns) error {
	return s.ztunnelServer.PodAdded(ctx, string(pod.UID), netns)
}

// ConstructInitialSnapshot takes a "snapshot" of current ambient pods and
//
// 1. Constructs a ztunnel state message to initialize ztunnel
// 2. Syncs the host ipset
func (s *NetServer) ConstructInitialSnapshot(ambientPods []*corev1.Pod) error {
	var consErr []error

	if err := s.buildZtunnelSnapshot(util.GetUniquePodUIDs(ambientPods)); err != nil {
		log.Warnf("failed to construct initial ztunnel snapshot: %v", err)
		consErr = append(consErr, err)
	}

	return errors.Join(consErr...)
}

func (s *NetServer) buildZtunnelSnapshot(ambientPodUIDs sets.Set[types.UID]) error {
	// first add all the pods as empty:
	for uid := range ambientPodUIDs {
		s.currentPodSnapshot.Ensure(string(uid))
	}

	// populate full pod snapshot from cgroups
	return s.scanProcForPodsAndCache(ambientPodUIDs)
}

func (s *NetServer) scanProcForPodsAndCache(filter sets.Set[types.UID]) error {
	// TODO: maybe remove existing uids in s.currentPodSnapshot from the filter set.
	res, err := s.podNs.FindNetnsForPods(filter)
	if err != nil {
		return err
	}

	for uid, netns := range res {
		s.currentPodSnapshot.UpsertPodCacheWithNetns(string(uid), netns)
	}
	return nil
}

func realDependencies() *dep.RealDependencies {
	return &dep.RealDependencies{
		CNIMode:          false, // we are in cni, but as we do the netns ourselves, we should keep this as false.
		NetworkNamespace: "",
	}
}

// Remove pod from mesh: pod is not deleted, we just want to remove it from the mesh.
func (s *NetServer) RemovePodFromMesh(ctx context.Context, pod *corev1.Pod) error {
	log := log.WithLabels("ns", pod.Namespace, "name", pod.Name)
	log.Debugf("Pod is now stopped or opt out... cleaning up.")

	openNetns := s.currentPodSnapshot.Take(string(pod.UID))
	if openNetns == nil {
		log.Warn("failed to find pod netns")
		return fmt.Errorf("failed to find pod netns")
	}
	// pod is removed from the mesh, but is still running. remove iptables rules
	log.Debugf("calling DeleteInpodRules.")
	if err := s.netnsRunner(openNetns, func() error { return s.iptablesConfigurator.DeleteInpodRules() }); err != nil {
		log.Errorf("failed to delete inpod rules %v", err)
		return fmt.Errorf("failed to delete inpod rules %w", err)
	}

	log.Debug("in pod mode - removing pod from ztunnel")
	if err := s.ztunnelServer.PodDeleted(ctx, string(pod.UID)); err != nil {
		log.Errorf("failed to delete pod from ztunnel: %v", err)
	}
	return nil
}

// Delete pod from mesh: pod is deleted. iptables rules will die with it, we just need to update ztunnel
func (s *NetServer) DelPodFromMesh(ctx context.Context, pod *corev1.Pod) error {
	log := log.WithLabels("ns", pod.Namespace, "name", pod.Name)
	log.Debug("Pod is now stopped or opt out... cleaning up.")

	log.Info("in pod mode - deleting pod from ztunnel")

	// pod is deleted, clean-up its open netns
	openNetns := s.currentPodSnapshot.Take(string(pod.UID))
	if openNetns == nil {
		log.Warn("failed to find pod netns")
	}

	if err := s.ztunnelServer.PodDeleted(ctx, string(pod.UID)); err != nil {
		return err
	}
	return nil
}
