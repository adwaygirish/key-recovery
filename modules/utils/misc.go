package utils

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"log"
	"math"
	"strconv"
)

func GetSmallerValue(val1, val2 int) int {
	if val1 < val2 {
		return val1
	} else {
		return val2
	}
}

// Helper function to convert interface{} to string
func ConvertToString(value interface{}) string {
	switch v := value.(type) {
	case int:
		return strconv.Itoa(v)
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case string:
		return v
	default:
		return "" // Handle other types as needed
	}
}

// nCr calculates the combination of n choose r
func GetCombination(n, r int) int {
	if r > n {
		return 0
	}
	val := 1
	if (n - r) > r {
		// fmt.Println("here")
		for i := n; i > (n - r); i-- {
			val *= i
		}
		// fmt.Println("done 1")
		val /= GetFactorial(r)
		// fmt.Println("done 2")
	} else {
		for i := n; i > r; i-- {
			val *= i
		}
		// fmt.Println("done 3")
		val /= GetFactorial(n - r)
		// fmt.Println("done 4")
	}
	return val
}

func GetLargeCombination(n, r int) [][]int {
	numerator := []int{}
	denominator := []int{}
	nullNumerator := make([]int, 0)
	nullNumerator = append(nullNumerator, 0)
	nullDenominator := make([]int, 0)
	nullDenominator = append(nullDenominator, 0)
	if r > n || r < 0 {
		return [][]int{nullNumerator, nullDenominator}
	}
	// fmt.Println("aa")
	if r == 0 || n == r {
		numerator = append(numerator, 1)
		denominator = append(denominator, 1)
	} else {
		if (n - r) > r {
			tempNum, num, tempDen, den := 1, 1, 1, 1
			for i := n; i > (n - r); i-- {
				tempNum *= i
				if tempNum >= 100000 {
					if i == (n - r + 1) {
						num = tempNum
					}
					numerator = append(numerator, num)
					tempNum, num = i, i
				} else {
					num = tempNum
					if i == (n - r + 1) {
						numerator = append(numerator, num)
					}
				}
			}
			for i := r; i >= 1; i-- {
				tempDen *= i
				if tempDen >= 100000 {
					denominator = append(denominator, den)
					tempDen, den = i, i
				} else {
					den = tempDen
					if i == (1) {
						denominator = append(denominator, den)
					}
				}
			}
		} else {
			tempNum, num, tempDen, den := 1, 1, 1, 1
			for i := n; i > r; i-- {
				tempNum *= i
				if tempNum >= 100000 {
					if i == (r + 1) {
						num = tempNum
					}
					numerator = append(numerator, num)
					tempNum, num = i, i
				} else {
					num = tempNum
					if i == (r + 1) {
						numerator = append(numerator, num)
					}
				}
			}
			for i := n - r; i >= 1; i-- {
				tempDen *= i
				if tempDen >= 100000 {
					denominator = append(denominator, den)
					tempDen, den = i, i
				} else {
					den = tempDen
					if i == (1) {
						denominator = append(denominator, den)
					}
				}
			}
		}
	}
	return [][]int{numerator, denominator}
}

func GetFraction(numerators, denominators []int) float64 {
	len1 := len(numerators)
	len2 := len(denominators)

	runLen1, runLen2 := 0, 0
	fracVal := float64(1)

	for {
		if runLen1 == len1 && runLen2 == len2 {
			break
		}
		if fracVal > float64(1000) {
			fracVal /= float64(denominators[runLen2])
			runLen2++
		} else {
			if runLen1 < len1 {
				// fmt.Println("xx")
				fracVal *= float64(numerators[runLen1])
				// fmt.Println("xy")
				runLen1++
			}
			if runLen2 < len2 {
				// fmt.Println("xx")
				fracVal /= float64(denominators[runLen2])
				runLen2++
				// fmt.Println("xy")
			}
		}
	}
	return fracVal
}

func GetFactorial(n int) int {
	if n < 0 {
		return -1 // Negative input, return error or handle accordingly
	}

	if n == 0 {
		return 1 // Base case: factorial of 0 is 1
	}

	result := 1
	for i := 1; i <= n; i++ {
		result *= i
	}
	return result
}

func ContainsZeros(slice []byte) bool {
	target := []byte{0, 0, 0, 0, 0, 0, 0, 0}
	for i := 0; i <= len(slice)-8; i++ {
		if bytes.Equal(slice[i:i+8], target) {
			return true
		}
	}
	return false
}

func DivideAndRound(a, b int) int {
	if b == 0 {
		panic("division by zero")
	}

	// Perform the integer division
	quotient := a / b
	remainder := a % b

	// Check the remainder and adjust the result
	if math.Abs(float64(remainder*2)) >= math.Abs(float64(b)) {
		if a*b > 0 {
			quotient++
		} else {
			quotient--
		}
	}

	return quotient
}

func FloorDivide(a, b int) int {
	if b == 0 {
		panic("division by zero")
	}

	return int(a / b)
}

func CeilDivide(a, b int) int {
	if b == 0 {
		panic("division by zero")
	}

	if a%b == 0 {
		return int(a / b)
	}

	return int(a/b) + 1
}

func FlipBitsWithProbability(arr []int, probability1, probability2 uint16,
	index1, index2 int) []int {
	copyArr := make([]int, len(arr))
	copy(copyArr, arr)
	max := uint16(100)
	buf := make([]byte, 2)
	count1 := 0
	count2 := 0
	for i := range copyArr[:index1] {
		_, err := rand.Read(buf)
		if err != nil {
			log.Fatalln(err)
		}

		randNum := binary.BigEndian.Uint16(buf) % max
		if randNum < probability1 {
			copyArr[i] = 1 - copyArr[i] // Flip the bit (0 becomes 1, 1 becomes 0)
			count1++
		}
	}
	// fmt.Println(copyArr[:index1], arr[:index1])

	for i := range copyArr[index1:index2] {
		_, err := rand.Read(buf)
		if err != nil {
			log.Fatalln(err)
		}

		randNum := binary.BigEndian.Uint16(buf) % max
		if randNum < probability2 {
			copyArr[index1+i] = 1 - copyArr[index1+i] // Flip the bit (0 becomes 1, 1 becomes 0)
			count2++
		}
	}

	// fmt.Println(count1, count2)
	return copyArr
}

func GenerateTrNonTrBitMatrix(trustees, contacts int) []int {
	result := make([]int, contacts)
	for i := 0; i < trustees; i++ {
		result[i] = 1
	}
	return result
}

func GenerateProbabilityArray(contacts int) ([]byte, error) {
	byteArray := make([]byte, contacts) // Each uint16 requires 2 bytes

	// Fill the byte slice with random data
	_, err := rand.Read(byteArray)
	if err != nil {
		return nil, err
	}

	for i := range byteArray {
		byteArray[i] = byteArray[i] % 100
	}

	return byteArray, nil
}
