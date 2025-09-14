package main

import (
	"fmt"

	"github.com/navid-m/zone/memory"
)

type Refdef struct {
	Health int32
	Pitch  float32
	Yaw    float32
	X      float32
	Y      float32
	Z      float32
}

func main() {
	for {
		var (
			refdef    Refdef
			val, _    = memory.ReadValue(memory.Float, "xonotic.exe", "0x621F8C")
			val2, _   = memory.ReadValue(memory.Float, "xonotic.exe", "0x621F90")
			val3, _   = memory.ReadValue(memory.Float, "xonotic.exe", "0x621F94")
			health, _ = memory.ReadValue(memory.FourBytes, "xonotic.exe", "0x627410")
		)

		refdef.X = val.(float32)
		refdef.Y = val2.(float32)
		refdef.Z = val3.(float32)
		refdef.Health = health.(int32)
		fmt.Println(refdef)
	}

	// reader := bufio.NewReader(os.Stdin)
	// reader.ReadString('\n')
}
