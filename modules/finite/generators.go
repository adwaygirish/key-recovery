package finite

import (
	"key_recovery/modules/utils"
)

// Gives the value of g^p mod (reducing polynomial)
func ModIntPowGF8(g, p uint8, l uint16) uint8 {
	if p == 0 {
		return uint8(1)
	}

	if p == 1 {
		return (g)
	}

	result := (g)
	for i := uint8(2); i <= p; i++ {
		tempResult := MultiplyGF8(result, g)
		result = LongDivisionRemainderGF8(tempResult, l)
		// fmt.Println(result)
	}
	return result
}

func ModIntPowGF16(n, p uint16, l uint32) uint16 {
	if p == 0 {
		return uint16(1)
	}

	if p == 1 {
		return (n)
	}

	result := (n)
	for i := uint16(2); i <= p; i++ {
		tempResult := MultiplyGF16(result, n)
		result = LongDivisionRemainderGF16(tempResult, l)
	}
	return result
}

func GetGenerator8(limit uint16) uint8 {
	prime := uint8(2)
	power := uint8(8)
	generator := uint8(0)
	runLimit := utils.IntPow8(prime, power) - 1
	for g := uint8(3); g < runLimit; g++ {
		generatedElements := make(map[uint8]int)
		for el := uint8(1); el < runLimit; el++ {
			generatedElements[el] = 0
		}
		for p := uint8(0); p < runLimit; p++ {
			val := ModIntPowGF8(g, p, limit)
			generatedElements[val] += 1
		}
		flag1 := true
		// flag2 := false
		for _, value := range generatedElements {
			if value == 0 {
				flag1 = false
				break
			}
		}
		if flag1 {
			generator = g
			break
		}
	}
	return generator
}

func GetAllGenerators8(limit uint16) []uint8 {
	prime := uint8(2)
	power := uint8(8)
	generator := GetGenerator8(limit)
	generators := make([]uint8, 0)
	generators = append(generators, (generator))
	runLimit := utils.IntPow8(prime, power) - 1
	for p := uint8(2); p < runLimit; p++ {
		if utils.GetGCD8(p, runLimit) == 1 {
			generators = append(generators, ModIntPowGF8(generator, p, limit))
		}
	}
	return generators
}

func GetGenerator16(limit uint32) uint16 {
	prime := uint16(2)
	power := uint16(16)
	generator := uint16(0)
	runLimit := utils.IntPow16(prime, power) - 1
	// fmt.Println(runLimit)
	for g := uint16(3); g < runLimit; g++ {
		generatedElements := make(map[uint16]int)
		for el := uint16(1); el < runLimit; el++ {
			generatedElements[el] = 0
		}
		for p := uint16(0); p < runLimit; p++ {
			val := ModIntPowGF16(g, p, limit)
			generatedElements[val] += 1
		}
		flag1 := true
		for _, value := range generatedElements {
			if value == 0 {
				flag1 = false
				break
			}
		}
		if flag1 {
			generator = g
			break
		}
	}
	return generator
}

func GetAllGenerators16(limit uint32) []uint16 {
	prime := uint16(2)
	power := uint16(16)
	generator := GetGenerator16(limit)
	generators := make([]uint16, 0)
	generators = append(generators, (generator))
	runLimit := utils.IntPow16(prime, power) - 1
	for p := uint16(2); p < runLimit; p++ {
		if utils.GetGCD16(p, runLimit) == 1 {
			generators = append(generators, ModIntPowGF16(generator, p, limit))
		}
	}
	return generators
}
