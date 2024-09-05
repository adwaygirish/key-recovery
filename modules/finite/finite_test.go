package finite

import (
	"testing"
)

func TestMultiplyGF16(t *testing.T) {
	testCases := []struct {
		a      uint16
		b      uint16
		result uint32
	}{
		{uint16(2), uint16(3), uint32(6)},
	}
	for _, tc := range testCases {
		result := MultiplyGF16(tc.a, tc.b)
		if result != tc.result {
			t.Error("Wrong output for", tc.a, tc.b, tc.result, result)
		}
	}
}

func TestMultiplyGF8(t *testing.T) {
	testCases := []struct {
		a      uint8
		b      uint8
		result uint16
	}{
		{uint8(2), uint8(3), uint16(6)},
		{uint8(232), uint8(2), uint16(464)},
		{uint8(20), uint8(200), uint16(4000)},
		{uint8(83), uint8(202), uint16(16254)},
	}
	for _, tc := range testCases {
		result := MultiplyGF8(tc.a, tc.b)
		if result != tc.result {
			t.Error("Wrong output for", tc.a, tc.b, tc.result, result)
		}
	}
}

func TestLongDivisionRemainderGF8(t *testing.T) {
	testCases := []struct {
		dividend uint16
		divisor  uint16
		result   uint8
	}{
		{uint16(16254), uint16(283), uint8(1)},
		{uint16(282), uint16(283), uint8(1)},
	}
	for _, tc := range testCases {
		result := LongDivisionRemainderGF8(tc.dividend, tc.divisor)
		if result != tc.result {
			t.Error("Wrong output for", tc.dividend, tc.divisor, tc.result, result)
		}
	}
}

func TestLongDivisionRemainderGF16(t *testing.T) {
	testCases := []struct {
		dividend uint32
		divisor  uint32
		result   uint16
	}{
		{uint32(69642), uint32(69643), uint16(1)},
	}
	for _, tc := range testCases {
		result := LongDivisionRemainderGF16(tc.dividend, tc.divisor)
		if result != tc.result {
			t.Error("Wrong output for", tc.dividend, tc.divisor, tc.result, result)
		}
	}
}
