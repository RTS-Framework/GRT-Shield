package main

import (
	"bytes"
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

	outMod  bool
	outPath string
)

func init() {
	flag.IntVar(&arch, "arch", 0, "specify the target architecture")
	flag.BoolVar(&opts.NoJunkCode, "njc", false, "not insert junk instruction to shield")
	flag.Int64Var(&opts.RandSeed, "seed", 0, "specify a random seed for generate shield")
	flag.StringVar(&opts.ShieldX86, "sid-x86", "", "specify the x86 shield template file path")
	flag.StringVar(&opts.ShieldX64, "sid-x64", "", "specify the x64 shield template file path")
	flag.StringVar(&jcx86, "junk-x86", "", "specify the x86 junk template directory path")
	flag.StringVar(&jcx64, "junk-x64", "", "specify the x64 junk template directory path")
	flag.BoolVar(&outMod, "mod", false, "output hex encoding module for develop")
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
	opts.JunkCodeX86 = loadJunkCodeTemplate(32, jcx86)
	opts.JunkCodeX64 = loadJunkCodeTemplate(64, jcx64)

	generator := shield.NewGenerator()
	var (
		ctx *shield.Context
		err error
	)
	for i := 0; i < 10; i++ {
		ctx, err = generator.Generate(arch, &opts)
		if err != nil {
			if err == shield.ErrShieldSizeTooLarge {
				fmt.Println("shield size too large, regenerate it")
				continue
			}
			checkError(err)
		}
		break
	}
	if ctx == nil {
		fmt.Println("regenerate shield too many times, please check template")
		os.Exit(1)
	}

	fmt.Println("==============Context===============")
	fmt.Println("seed:", ctx.Seed)
	fmt.Println("size:", len(ctx.Output))
	fmt.Println("====================================")
	fmt.Println(ctx.ShieldInst)
	fmt.Println("====================================")
	fmt.Println()

	output := ctx.Output
	if outMod {
		// aligned to the memory page size
		pad := bytes.Repeat([]byte{0x00}, shield.MaxShieldSize-len(output))
		output = append(output, pad...)
		output = dumpModule(output)
	}
	err = os.WriteFile(outPath, output, 0600) // #nosec
	checkError(err)
	fmt.Printf("save output shield to \"%s\"\n", outPath)

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
	if outMod {
		outPath += ".inst"
	} else {
		outPath += ".bin"
	}
}

func loadJunkCodeTemplate(arch int, dir string) []string {
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
		name := file.Name()
		if filepath.Ext(name) != ".asm" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, name)) // #nosec
		checkError(err)
		template := string(data)
		_, _, err = shield.InspectJunkCodeTemplate(arch, template)
		checkError(err)
		templates = append(templates, template)
	}
	return templates
}

func dumpModule(b []byte) []byte {
	n := len(b)
	builder := bytes.Buffer{}
	builder.Grow(len("0FFh, ")*n - len(", "))
	buf := make([]byte, 2)
	var counter = 0
	for i := 0; i < n; i++ {
		if counter == 0 {
			builder.WriteString("  db ")
		}
		hex.Encode(buf, b[i:i+1])
		builder.WriteString("0")
		builder.Write(bytes.ToUpper(buf))
		builder.WriteString("h")
		if i == n-1 {
			builder.WriteString("\r\n")
			break
		}
		counter++
		if counter != 16 {
			builder.WriteString(", ")
			continue
		}
		counter = 0
		builder.WriteString("\r\n")
	}
	return builder.Bytes()
}

func checkError(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
