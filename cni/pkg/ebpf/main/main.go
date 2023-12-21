package main

import (
	"istio.io/istio/cni/pkg/ebpf"
)

func main() {
	err := ebpf.LoadPrograms()
	if err != nil {
		panic(err)
	}
}
