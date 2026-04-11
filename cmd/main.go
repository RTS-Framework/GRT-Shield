package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/RTS-Framework/GRT-Shield"
)

var (
	arch  int
	jcx86 string
	jcx64 string
	opts  shield.Options

	outHex  bool
	outPath string
)

func init() {
	flag.IntVar(&arch, "arch", 0, "specify the target architecture")
	flag.BoolVar(&opts.NoGarbage, "ngi", false, "not append garbage instruction to shield")
	flag.Int64Var(&opts.RandSeed, "seed", 0, "specify a random seed for generate loader")
	flag.StringVar(&opts.ShieldX86, "sid-x86", "", "specify the x86 shield template file path")
	flag.StringVar(&opts.ShieldX64, "sid-x64", "", "specify the x64 shield template file path")
	flag.StringVar(&jcx86, "junk-x86", "", "specify the x86 junk template directory path")
	flag.StringVar(&jcx64, "junk-x64", "", "specify the x64 junk template directory path")
	flag.BoolVar(&outHex, "hex", false, "use hexadecimal encoding for output")
	flag.StringVar(&outPath, "out", "", "specify the output file path")
	flag.Parse()
}

func main() {
	if arch == 0 {
		flag.Usage()
		return
	}
	if outPath == "" {
		setDefaultOutputName()
	}
	opts.JunkCodeX86 = loadJunkCodeTemplate(jcx86)
	opts.JunkCodeX64 = loadJunkCodeTemplate(jcx64)

	generator := shield.NewGenerator()

	ctx, err := generator.Generate(arch, &opts)
	checkError(err)
	fmt.Println("seed:", ctx.Seed)
	fmt.Printf("save shield to \"%s\"\n", outPath)
	output := ctx.Output
	if outHex {
		output = []byte(hex.EncodeToString(output))
	}
	err = os.WriteFile(outPath, output, 0600) // #nosec
	checkError(err)

	err = generator.Close()
	checkError(err)
}

func setDefaultOutputName() {
	switch arch {
	case 32:
		outPath = "shield_x86"
	case 64:
		outPath = "shield_x64"
	}
	if outHex {
		outPath += ".hex"
	} else {
		outPath += ".bin"
	}
}

func loadJunkCodeTemplate(dir string) []string {
	if dir == "" {
		return nil
	}
	fmt.Println("load custom junk code template directory:", dir)
	files, err := os.ReadDir(dir)
	checkError(err)
	templates := make([]string, 0, len(files))
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, file.Name())) // #nosec
		checkError(err)
		src := string(data)
		_, _, err = shield.InspectJunkCodeTemplate(arch, src)
		checkError(err)
		templates = append(templates, src)
	}
	return templates
}

func checkError(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
