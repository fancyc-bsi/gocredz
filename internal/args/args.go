// internal/args/args.go

package args

import (
	"flag"
	"fmt"
	"gnc/pkg/types"
	"os"
	"strings"
)

// ParseFlags parses command line arguments and returns a Config
func ParseFlags() *types.Config {
	conf := &types.Config{}

	flag.StringVar(&conf.Interface, "i", "", "Interface to capture on")
	flag.StringVar(&conf.PcapFile, "f", "", "PCAP file to read")
	flag.BoolVar(&conf.Debug, "d", false, "Enable debug mode")
	flag.IntVar(&conf.Verbose, "v", 0, "Verbosity level")
	flag.BoolVar(&conf.ShowVersion, "version", false, "Show version information")

	var filters string
	flag.StringVar(&filters, "c", "all", "Comma-separated capture methods")
	flag.StringVar(&conf.Regex, "r", "", "Custom regex pattern")
	flag.StringVar(&conf.OutputPath, "o", "gocredz_output", "Output file path (without extension)")
	flag.BoolVar(&conf.JSONOutput, "json", false, "Enable JSON output format")

	flag.Parse()

	if !conf.ShowVersion && conf.Interface == "" && conf.PcapFile == "" {
		fmt.Println("Either interface (-i) or pcap file (-f) must be specified")
		os.Exit(1)
	}

	conf.Filters = strings.Split(filters, ",")
	return conf
}
