package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/RTS-Framework/GRT-Shield"
)

var (
	arch  int
	jcx86 string
	jcx64 string
	opts  shield.Options
	hex   bool
	out   string
)

func init() {
	flag.IntVar(&arch, "arch", 0, "specify the target architecture")
	flag.BoolVar(&opts.NoGarbage, "ngi", false, "not append garbage instruction to shield")
	flag.Int64Var(&opts.RandSeed, "seed", 0, "specify a random seed for generate loader")
	flag.StringVar(&opts.ShieldX86, "sid-x86", "", "specify the x86 shield template file path")
	flag.StringVar(&opts.ShieldX64, "sid-x64", "", "specify the x64 shield template file path")
	flag.StringVar(&jcx86, "junk-x86", "", "specify the x86 junk template directory path")
	flag.StringVar(&jcx64, "junk-x64", "", "specify the x64 junk template directory path")
	flag.BoolVar(&hex, "hex", false, "use hexadecimal encoding for output")
	flag.StringVar(&out, "o", "", "specify the output file path")
	flag.Parse()
}

func main() {
	if arch == 0 {
		flag.Usage()
		return
	}

	if out == "" {
		setDefaultOutputName()
	}

	generator := shield.NewGenerator()

	err := generator.Close()
	checkError(err)
}

func setDefaultOutputName() {
	switch arch {
	case 32:
		out = "shield_x86"
	case 64:
		out = "shield_x64"
	}
	if hex {
		out += ".hex"
	} else {
		out += ".bin"
	}
}

func checkError(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
