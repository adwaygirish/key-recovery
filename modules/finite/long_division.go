package finite

func LongDivisionRemainderGF8(dividend uint16, divisor uint16) uint8 {
	remainder := dividend
	flag := false
	for i := 16; i > 8; i-- {
		numCheck := dividend >> (i - 1)
		if numCheck != 0 && !flag {
			flag = true
		}
		if flag {
			divisor16 := (divisor) << (i - 9)
			if remainder/divisor16 >= 1 || divisor16/remainder == 1 {
				remainder = remainder ^ divisor16
			}
		}
	}
	return uint8(remainder)
}

func LongDivisionRemainderGF16(dividend uint32, divisor uint32) uint16 {
	remainder := dividend
	flag := false
	for i := 32; i > 16; i-- {
		// Start taking the XORs after the first 1
		numCheck := dividend >> (i - 1)
		if numCheck != 0 && !flag {
			flag = true
		}
		if flag {
			divisor32 := (divisor) << (i - 17)
			// If there is a leading 0,
			// then you should not be dividing
			// because the number is smaller than the divisor
			if remainder/divisor32 >= 1 || divisor32/remainder == 1 {
				remainder = remainder ^ divisor32
			}
		}
	}
	return uint16(remainder)
}
