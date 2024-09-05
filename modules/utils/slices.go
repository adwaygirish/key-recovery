package utils

import (
	"log"
	randm "math/rand"
	"slices"
	"time"
)

// This is finding the index of the maximum element in a slice
func FindMaxElementIndex(data []float64) int {
	if len(data) == 0 {
		return -1
	} else {
		index := 0
		for i, val := range data {
			if val > data[index] {
				index = i
			}
		}
		return index
	}
}

// Finds the maximum element in an integer
func FindMaxElementIndexInt(data []int) int {
	if len(data) == 0 {
		return -1
	} else {
		index := 0
		for i, val := range data {
			if val > data[index] {
				index = i
			}
		}
		return index
	}
}

// Checks if an element is present inside a slice
func IsInSlice(slice []int, element int) bool {
	return slices.Contains[[]int, int](slice, element)
}

// Checks if an element is present inside a slice
func IsInSliceUint16(slice []uint16, element uint16) bool {
	return slices.Contains[[]uint16, uint16](slice, element)
}

// Removing an element from a slice
// Also, gives a boolean with the output which indicates
// if an element was removed or not
func RemoveElement(slice []int, index int) ([]int, bool) {
	if index >= len(slice) {
		return []int{}, false
	} else {
		if index == len(slice)-1 {
			return slice[:len(slice)-1], true
		} else {
			return append(slice[:index], slice[index+1:]...), true
		}
	}
}

// Find the elements in a slice which are less than a given number
func CountLessThan(nums []int, target int) int {
	count := 0
	for _, num := range nums {
		if num < target {
			count++
		}
	}
	return count
}

// Get the index of an element in a slice
func GetIndex(slice []int, target int) int {
	for i, value := range slice {
		if value == target {
			return i // Return the index of the target element
		}
	}
	return -1 // Return -1 if the target element is not found
}

// Shuffles the elements of a slice
func Shuffle(slice []int) {
	source := randm.NewSource(time.Now().UnixNano()) // Seed the random number generator
	rng := randm.New(source)
	// Fisher-Yates shuffle algorithm
	for i := len(slice) - 1; i > 0; i-- {
		j := rng.Intn(i + 1)
		slice[i], slice[j] = slice[j], slice[i]
	}
}

// intersection finds the intersection of two integer slices
func GetIntersection(nums1, nums2 []int) []int {
	intersect := make(map[int]bool) // Map to store intersection elements
	result := []int{}

	// Store elements of nums1 in the map
	for _, num := range nums1 {
		intersect[num] = true
	}

	// Check elements of nums2 against the map
	for _, num := range nums2 {
		if intersect[num] {
			result = append(result, num)
		}
	}

	return result
}

func GetIntersectionUint16(nums1, nums2 []uint16) []uint16 {
	intersect := make(map[uint16]bool) // Map to store intersection elements
	result := []uint16{}

	// Store elements of nums1 in the map
	for _, num := range nums1 {
		intersect[num] = true
	}

	// Check elements of nums2 against the map
	for _, num := range nums2 {
		if intersect[num] {
			result = append(result, num)
		}
	}

	return result
}

// sumSlice calculates the sum of all elements in the slice
func GetSumSlice(nums []int) int {
	sum := 0
	for _, num := range nums {
		sum += num
	}
	return sum
}

// Get the product of all the elements of the slice
func GetProduct(slice []int) int {
	product := 1
	for _, element := range slice {
		product = product * element
	}
	return product
}

// Check if all the elements of the slice are the same
func CheckAllElementsSame(slice []int) bool {
	first := slice[0]
	check := true
	for _, element := range slice {
		if first != element {
			check = false
			break
		}
	}
	return check
}

// RemoveAt removes an element from a slice at the specified index and returns the removed element
func RemoveAt(slice *[]int, index int) int {
	// Ensure index is within the bounds of the slice
	if index < 0 || index >= len(*slice) {
		log.Fatalln("Index out of bounds")
	}

	removedElement := (*slice)[index]
	*slice = append((*slice)[:index], (*slice)[index+1:]...)
	return removedElement
}

// InsertAt inserts an element into a slice at the specified index
func InsertAt(slice *[]int, index int, value int) {
	// Ensure index is within the bounds of the slice
	if index < 0 || index > len(*slice) {
		log.Fatalln("Index out of bounds")
		return
	}

	// Append the value to the slice (creating space at the end)
	*slice = append(*slice, 0)

	// Shift elements from the index to the right by one position
	copy((*slice)[index+1:], (*slice)[index:])

	// Insert the new value at the specified index
	(*slice)[index] = value
}

// MoveElement removes an element from one index and inserts it into another index
func MoveElement(slice *[]int, fromIndex int, toIndex int) {
	// Remove the element from the original index
	removedElement := RemoveAt(slice, fromIndex)

	// Insert the removed element at the new index
	InsertAt(slice, toIndex, removedElement)
}

func UpdateOrder(hintedPeople []int, accessOrder *[]int,
	obtainedLength int) {
	if obtainedLength == len(*accessOrder) {
		return
	}
	tempSlice := (*accessOrder)[:obtainedLength]
	approachedSlice := make([]int, len(tempSlice))
	copy(approachedSlice, tempSlice)
	for i := 0; i < len(hintedPeople); i++ {
		if IsInSlice(approachedSlice, hintedPeople[i]) ||
			GetIndex((*accessOrder), hintedPeople[i]) == obtainedLength {
			continue
		} else {
			oldIndex := GetIndex((*accessOrder), hintedPeople[i])
			newIndex := obtainedLength
			for {
				if !IsInSlice(hintedPeople, (*accessOrder)[newIndex]) {
					break
				}
				newIndex++
				if newIndex == len(*accessOrder)-1 {
					break
				}
			}
			if oldIndex != newIndex {
				MoveElement(accessOrder, oldIndex, newIndex)
			}
		}
	}
}

func UpdateOrderBinExt(hintedPeople []int, accessOrder *[]int,
	obtainedLength int) {
	if obtainedLength == len(*accessOrder) {
		return
	}
	tempSlice := (*accessOrder)[:obtainedLength]
	approachedSlice := make([]int, len(tempSlice))
	copy(approachedSlice, tempSlice)
	for i := 0; i < len(hintedPeople); i++ {
		if IsInSlice(approachedSlice, hintedPeople[i]-1) ||
			GetIndex((*accessOrder), hintedPeople[i]-1) == obtainedLength {
			continue
		} else {
			oldIndex := GetIndex((*accessOrder), hintedPeople[i]-1)
			newIndex := obtainedLength
			for {
				if !IsInSlice(hintedPeople, (*accessOrder)[newIndex]) {
					break
				}
				newIndex++
				if newIndex == len(*accessOrder)-1 {
					break
				}
			}
			if oldIndex != newIndex {
				MoveElement(accessOrder, oldIndex, newIndex)
			}
		}
	}
}

func AllTrue(slice []bool) bool {
	for _, v := range slice {
		if !v {
			return false
		}
	}
	return true
}
