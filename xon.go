package main

import (
	"fmt"
	"zone/memory"
)

func main() {
	err := memory.ChangeValue(memory.FourBytes, "xonotic-x86.exe", "0x5963B4", int32(9999))
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Println("Value changed successfully!")
}
