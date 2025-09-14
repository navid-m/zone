package main

import (
	"fmt"

	"github.com/navid-m/zone/memory"
)

type Vector3 struct {
	X float32
	Y float32
	Z float32
}

type Refdef struct {
	Health int32
	Ammo   int32
	Pitch  float32
	Yaw    float32
	Coords Vector3
}

type Entity struct {
	Coords Vector3
}

func main() {
	for {
		var (
			refdef    Refdef
			val, _    = memory.ReadValue(memory.Float, "xonotic.exe", "0x621F8C")
			val2, _   = memory.ReadValue(memory.Float, "xonotic.exe", "0x621F90")
			val3, _   = memory.ReadValue(memory.Float, "xonotic.exe", "0x621F94")
			health, _ = memory.ReadValue(memory.FourBytes, "xonotic.exe", "0x627410")
			pitch, _  = memory.ReadValue(memory.Float, "xonotic.exe", "0x621F68")
			yaw, _    = memory.ReadValue(memory.Float, "xonotic.exe", "0x621F6C")
			ammo, _   = memory.ReadValue(memory.FourBytes, "xonotic.exe", "0x627428")
		)

		refdef.Coords.X = val.(float32)
		refdef.Coords.Y = val2.(float32)
		refdef.Coords.Z = val3.(float32)
		refdef.Pitch = pitch.(float32)
		refdef.Yaw = yaw.(float32)
		refdef.Health = health.(int32)
		refdef.Ammo = ammo.(int32)

		fmt.Println(refdef)
	}

	// reader := bufio.NewReader(os.Stdin)
	// reader.ReadString('\n')
}
