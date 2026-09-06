package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/smshagor-dev/ZeroTrust-FL-Sim/internal/protocompat"
)

func main() {
	baseline := flag.String("baseline", "", "path to the published baseline FileDescriptorSet")
	current := flag.String("current", "", "path to the proposed FileDescriptorSet")
	flag.Parse()

	if *baseline == "" || *current == "" {
		fmt.Fprintln(os.Stderr, "both --baseline and --current descriptor paths are required")
		os.Exit(2)
	}
	if err := protocompat.CheckFiles(*baseline, *current); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("protobuf compatibility check passed")
}
