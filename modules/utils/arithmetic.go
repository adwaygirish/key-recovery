package utils

func IntPow(n, p int) int {
	if p == 0 {
		return 1
	}

	if p == 1 {
		return n
	}

	result := n
	for i := 2; i <= p; i++ {
		result *= n
	}
	return result
}

func IntPow8(n, p uint8) uint8 {
	if p == 0 {
		return 1
	}

	if p == 1 {
		return n
	}

	result := n
	for i := uint8(2); i <= p; i++ {
		result *= n
	}
	return result
}

func IntPow16(n, p uint16) uint16 {
	if p == 0 {
		return 1
	}

	if p == 1 {
		return n
	}

	result := n
	for i := uint16(2); i <= p; i++ {
		result *= n
	}
	return result
}

func GetGCD8(a, b uint8) uint8 {
	for b != 0 {
		a, b = b, a%b
	}
	return a
}

func GetGCD16(a, b uint16) uint16 {
	for b != 0 {
		a, b = b, a%b
	}
	return a
}
