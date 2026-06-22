package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/funnybones69/tamizdat/node"
)

func splitList(raw string) []string {
	var out []string
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func usage() {
	fmt.Fprintf(os.Stderr, "usage: tamizdat-geo [-geoip file[,file...]] [-geosite file[,file...]] <cidrs|domains> <group>\n")
	flag.PrintDefaults()
}

func main() {
	geoip := flag.String("geoip", "", "comma-separated geoip.dat paths")
	geosite := flag.String("geosite", "", "comma-separated geosite.dat paths")
	flag.Usage = usage
	flag.Parse()
	if flag.NArg() != 2 {
		usage()
		os.Exit(2)
	}
	mode, group := flag.Arg(0), flag.Arg(1)
	db, err := node.LoadGeoDBMulti(splitList(*geoip), splitList(*geosite))
	if err != nil {
		log.Fatal(err)
	}
	switch mode {
	case "cidrs":
		for _, p := range db.GeoIPCIDRs(group) {
			fmt.Println(p.String())
		}
	case "domains":
		for _, d := range db.GeositeDomainValues(group) {
			fmt.Println(d)
		}
	default:
		usage()
		os.Exit(2)
	}
}
