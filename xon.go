package main

import (
	"bufio"
	"fmt"
	"os"

	"github.com/navid-m/zone/memory"
)

func main() {
	err := memory.FreezeValue(memory.FourBytes, "xonotic-x86.exe", "0x5963B4", int32(9999))
	err = memory.FreezeValue(memory.FourBytes, "xonotic-x86.exe", "0x596390", int32(9999))
	health, err := memory.ReadValue(memory.FourBytes, "xonotic-x86.exe", "0x596390")

	fmt.Println(health)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	reader := bufio.NewReader(os.Stdin)
	reader.ReadString('\n')
}
