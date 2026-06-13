# GRT-Shield
A package for deep customization of Gleam-RT shield. It supports custom shield and junk code templates with register randomization.

## Usage
```bash
shield -arch 64 -out shield_x64.bin
shield -arch 32 -seed 1234 -out shield_x86.bin
```

## Development
```go
package main

import (
    "encoding/hex"
    "fmt"
    "os"

    "github.com/RTS-Framework/GRT-Shield"
)

func main() {
    generator := shield.NewGenerator()

    opts := shield.Options{
        NoJunkCode: false,
        RandSeed:   0,
    }

    ctx, err := generator.Generate(64, &opts)
    checkError(err)

    fmt.Println("seed:", ctx.Seed)
    fmt.Println("size:", len(ctx.Output))
    fmt.Println(ctx.Inst)

    err = generator.Close()
    checkError(err)
}

func checkError(err error) {
    if err != nil {
        fmt.Println(err)
        os.Exit(1)
    }
}
```

## Disclaimer
This project is developed solely for security research, educational purposes, and authorized penetration testing.\
Any use for illegal activities, unauthorized access to computer systems, or malicious purposes is strictly prohibited.

By using this project, you agree that:

1. You will only use it in environments you own or have explicit authorization to test.
2. You are solely responsible for ensuring compliance with all applicable local, state, national, and international laws and regulations.
3. The authors and contributors assume no liability and are not responsible for any misuse or damage ca +used by this project.
4. You understand that unauthorized use of computer systems is a criminal offense in most jurisdictions

This software is provided "as is" without warranty of any kind, express or implied. Use at your own risk.
