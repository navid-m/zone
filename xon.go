package main

import (
	"fmt"

	"github.com/navid-m/zone/memory"
)

func main() {
	// err := memory.FreezeValue(memory.FourBytes, "xonotic-x86.exe", "0x5963B4", int32(9999))
	// err = memory.FreezeValue(memory.FourBytes, "xonotic-x86.exe", "0x596390", int32(9999))

	for {
		entityOneZ, err := memory.ReadPointerChain(memory.FourBytes, "xonotic.exe", "0x0120A558", []string{"0x60", "0x80", "0x528", "0xFC0", "0x10"})
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Println(entityOneZ)

	}
	// reader := bufio.NewReader(os.Stdin)
	// reader.ReadString('\n')
}
