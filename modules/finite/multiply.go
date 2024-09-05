package finite

// Multiplication in GF(2^8)
func MultiplyGF8(a, b uint8) uint16 {
	var result uint16 = 0 // Result can be up to 16 bits

	// Go through each bit of b
	for i := 0; i < 8; i++ {
		// Check if the i-th bit of b is set (1)
		// When the bit is 0, you do not need to do anything
		if (b & (1 << i)) != 0 {
			// If it's set, add (a shifted left by i) to the result
			result ^= uint16(a) << i
		}
	}

	return result
}

// Multiplication in GF(2^16)
func MultiplyGF16(a, b uint16) uint32 {
	var result uint32 = 0 // Result can be up to 32 bits

	// Go through each bit of b
	for i := 0; i < 16; i++ {
		// Check if the i-th bit of b is set (1)
		// When the bit is 0, you do not need to do anything
		if (b & (1 << i)) != 0 {
			// If it's set, add (a shifted left by i) to the result
			result ^= uint32(a) << i
		}
	}

	return result
}

// Multiplication in GF(2^32)
func MultiplyGF32(a, b uint32) uint64 {
	var result uint64 = 0 // Result can be up to 64 bits

	// Go through each bit of b
	for i := 0; i < 32; i++ {
		// Check if the i-th bit of b is set (1)
		// When the bit is 0, you do not need to do anything
		if (b & (1 << i)) != 0 {
			// If it's set, add (a shifted left by i) to the result
			result ^= uint64(a) << i
		}
	}

	return result
}
