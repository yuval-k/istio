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
	"net/http"
	"sync/atomic"

	"istio.io/istio/cni/pkg/constants"
)

// StartServer initializes and starts a web server that exposes liveness and readiness endpoints at port 8000.
func StartHealthServer() (*atomic.Value, *atomic.Value) {
	router := http.NewServeMux()
	installReady, watchReady := initRouter(router)

	go func() {
		_ = http.ListenAndServe(":"+constants.ReadinessPort, router)
	}()

	return installReady, watchReady
}

func initRouter(router *http.ServeMux) (*atomic.Value, *atomic.Value) {
	installDaemonReady := &atomic.Value{}
	watchServerReady := &atomic.Value{}
	installDaemonReady.Store(false)
	watchServerReady.Store(false)

	router.HandleFunc(constants.LivenessEndpoint, healthz)
	router.HandleFunc(constants.ReadinessEndpoint, readyz(installDaemonReady, watchServerReady))

	return installDaemonReady, watchServerReady
}

func healthz(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func readyz(installReady, watchReady *atomic.Value) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		if (installReady == nil || !installReady.Load().(bool)) || (watchReady == nil || !watchReady.Load().(bool)) {
			http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}
}
