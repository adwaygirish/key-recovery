package finite

import (
	"key_recovery/modules/utils"
)

func GenerateExpTable8(generator uint8, limit uint16) []uint8 {
	expTable := make([]uint8, 0)
	prime := uint8(2)
	power := uint8(8)
	runLimit := utils.IntPow8(prime, power) - 1
	for i := uint8(0); i < runLimit; i++ {
		val := ModIntPowGF8(generator, i, limit)
		expTable = append(expTable, val)
	}
	expTable = append(expTable, uint8(0))
	return expTable
}

func GenerateLogTable8(generator uint8, limit uint16) []uint8 {
	logTable := make([]uint8, 256)
	logTable[0] = 0
	prime := uint8(2)
	power := uint8(8)
	runLimit := utils.IntPow8(prime, power) - 1
	for i := uint8(0); i < runLimit; i++ {
		index := ModIntPowGF8(generator, i, limit)
		logTable[index] = i
	}
	return logTable
}

func GenerateExpTable16(generator uint16, limit uint32) []uint16 {
	expTable := make([]uint16, 0)
	prime := uint16(2)
	power := uint16(16)
	runLimit := utils.IntPow16(prime, power) - 1
	for i := uint16(0); i < runLimit; i++ {
		val := ModIntPowGF16(generator, i, limit)
		expTable = append(expTable, val)
	}
	expTable = append(expTable, uint16(0))
	return expTable
}

func GenerateLogTable16(generator uint16, limit uint32) []uint16 {
	logTable := make([]uint16, 65536)
	logTable[0] = 0
	prime := uint16(2)
	power := uint16(16)
	runLimit := utils.IntPow16(prime, power) - 1
	for i := uint16(0); i < runLimit; i++ {
		index := ModIntPowGF16(generator, i, limit)
		logTable[index] = i
	}
	return logTable
}
