package shamir

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"key_recovery/modules/errors"
	"key_recovery/modules/files"
	"key_recovery/modules/utils"
	"log"
)

const TotalLength = 65536

type Field struct {
	expTable, logTable [TotalLength]uint16
}

type PriShare struct {
	X uint16
	Y []uint16
}

func (f *Field) InitializeTables() {
	table, err := files.LoadSlice16FromFile("expTable_16.gob")
	if err != nil {
		log.Fatalln(err)
	}
	copy(f.expTable[:], table)
	table, err = files.LoadSlice16FromFile("logTable_16.gob")
	if err != nil {
		log.Fatalln(err)
	}
	copy(f.logTable[:], table)
}

// an x/y pair
type pair struct {
	x, y uint16
}

// polynomial represents a polynomial of arbitrary degree
type polynomial struct {
	coefficients []uint16
}

// makePolynomial constructs a random polynomial of the given
// degree but with the provided intercept value.
func makePolynomial(intercept, degree uint16) (polynomial, error) {
	// Create a wrapper
	p := polynomial{
		coefficients: make([]uint16, degree+1),
	}

	// Ensure the intercept is set
	p.coefficients[0] = intercept

	var b [2]byte

	for i := 1; i < len(p.coefficients); i++ {
		_, err := rand.Read(b[:])
		if err != nil {
			log.Fatalln(err)
		}
		// Convert the bytes into a uint16
		randomUint16 := binary.BigEndian.Uint16(b[:])
		p.coefficients[i] = randomUint16
	}

	return p, nil
}

// evaluate returns the value of the polynomial for the given x
func (f *Field) evaluate(x uint16, p polynomial) uint16 {
	// Special case the origin
	if x == 0 {
		return p.coefficients[0]
	}

	// Compute the polynomial value using Horner's method.
	degree := len(p.coefficients) - 1
	out := p.coefficients[degree]
	for i := degree - 1; i >= 0; i-- {
		coeff := p.coefficients[i]
		out = Add(f.Mult(out, x), coeff)
	}
	return out
}

// Lagrange interpolation
//
// Takes N sample points and returns the value at a given x using a lagrange interpolation.
func (f *Field) interpolate(points []pair, x uint16) (value uint16) {
	for i, a := range points {
		weight := uint16(1)
		for j, b := range points {
			if i != j {
				top := x ^ b.x
				bottom := a.x ^ b.x
				if bottom == 0 {
					fmt.Println(points)
				}
				factor := f.Div(top, bottom)
				weight = f.Mult(weight, factor)
			}
		}
		value = value ^ f.Mult(weight, a.y)
	}
	return value
}

// Div Divides two numbers in GF(2^16)
func (f *Field) Div(a, b uint16) uint16 {
	if b == 0 {
		// leaks some timing information but we don't care anyways as this
		// should never happen, hence the panic
		fmt.Println(a, b)
		panic("Divide by zero")
	}

	var goodVal, zero uint16
	log_a := f.logTable[a]
	log_b := f.logTable[b]
	diff := (int(log_a) - int(log_b)) % int(TotalLength-1)
	if diff < 0 {
		diff += (TotalLength - 1)
	}

	ret := f.expTable[diff]

	// Ensure we return zero if a is zero but aren't subject to timing attacks
	goodVal = ret
	bytesArray := make([]byte, 2)
	zeroArray := make([]byte, 2)
	binary.BigEndian.PutUint16(bytesArray, a)

	if subtle.ConstantTimeCompare(bytesArray, zeroArray) == 1 {
		ret = zero
	} else {
		ret = goodVal
	}

	return ret
}

// Mult Multiplies two numbers in GF(2^16)
func (f *Field) Mult(a, b uint16) (out uint16) {
	var goodVal, zero uint16
	log_a := f.logTable[a]
	log_b := f.logTable[b]
	sum := (int(log_a) + int(log_b)) % int(TotalLength-1)

	ret := f.expTable[sum]

	// Ensure we return zero if either a or be are zero but aren't subject to
	// timing attacks
	goodVal = ret
	bytesArray := make([]byte, 2)
	zeroArray := make([]byte, 2)
	binary.BigEndian.PutUint16(bytesArray, a)

	if subtle.ConstantTimeCompare(bytesArray, zeroArray) == 1 {
		ret = zero
	} else {
		ret = goodVal
	}

	binary.BigEndian.PutUint16(bytesArray, b)
	if subtle.ConstantTimeCompare(bytesArray, zeroArray) == 1 {
		ret = zero
	} else {
		// This operation does not do anything logically useful. It
		// only ensures a constant number of assignments to thwart
		// timing attacks.
		goodVal = zero
	}

	return ret
}

// Add combines two numbers in GF(2^16)
// This can also be used for subtraction since it is symmetric.
func Add(a, b uint16) uint16 {
	return a ^ b
}

func SliceAdd(a, b []uint16) ([]uint16, error) {
	if len(a) != len(b) {
		return nil, errors.ErrInvalidSliceLength
	}
	output := make([]uint16, len(a))
	for i := 0; i < len(a); i++ {
		output[i] = a[i] ^ b[i]
	}
	return output, nil
}

// Split takes an arbitrarily long secret and generates a `parts`
// number of shares, `threshold` of which are required to reconstruct
// the secret. The parts and threshold must be at least 2, and less
// than 65536.
func (f *Field) Split(secret []uint16, parts, threshold int) (map[uint16][]uint16, []polynomial, error) {
	out := make(map[uint16][]uint16)
	ps := make([]polynomial, 0)

	// Generate x-coordinates for each of the parts
	buf := make([]byte, 2)
	for len(out) < parts {
		if _, err := rand.Read(buf); err != nil {
			return nil, nil, err
		}
		x := binary.BigEndian.Uint16(buf)
		// We cannot use a zero x coordinate otherwise the y values
		// would be the intercepts i.e. the secret value itself.
		if x == 0 {
			continue
		}
		// If the x-coordinate repeats, do not store it again
		if _, exists := out[x]; exists {
			continue
		}
		out[x] = []uint16{}
	}

	for _, s := range secret {
		// For every two bytes of the secret, generate a polynomial
		p, err := makePolynomial(s, uint16(threshold-1))
		if err != nil {
			log.Fatalln(err)
		}

		for x := range out {
			y := f.evaluate(x, p)
			out[x] = append(out[x], y)
		}
		ps = append(ps, p)
	}

	// Return the encoded secrets
	return out, ps, nil
}

func (f *Field) SplitUniqueX(secret []uint16, parts, threshold int,
	xUsedCoords *[]uint16) ([]PriShare, []polynomial, error) {
	out := make([]PriShare, 0)
	ps := make([]polynomial, 0)

	// Generate x-coordinates for each of the parts
	buf := make([]byte, 2)
	for len(out) < parts {
		if _, err := rand.Read(buf); err != nil {
			return nil, nil, err
		}
		x := binary.BigEndian.Uint16(buf)
		// We cannot use a zero x coordinate otherwise the y values
		// would be the intercepts i.e. the secret value itself.
		if x == 0 {
			continue
		}
		// Check if the x-coordinate has been already used
		exists := utils.IsInSliceUint16((*xUsedCoords), x)
		// If the x-coordinate repeats, do not store it again
		if exists {
			continue
		}
		(*xUsedCoords) = append((*xUsedCoords), x)
		out = append(out, PriShare{X: x, Y: []uint16{}})
	}

	for _, s := range secret {
		// For every two bytes of the secret, generate a polynomial
		p, err := makePolynomial(s, uint16(threshold-1))
		if err != nil {
			log.Fatalln(err)
		}

		for ind, val := range out {
			y := f.evaluate(val.X, p)
			out[ind].Y = append(out[ind].Y, y)
		}
		ps = append(ps, p)
	}

	// Return the encoded secrets
	return out, ps, nil
}

func (f *Field) Combine(parts map[uint16][]uint16) ([]uint16, error) {
	// Verify enough parts provided
	if len(parts) < 2 {
		return nil, fmt.Errorf("less than two parts cannot be used to reconstruct the secret")
	}

	// Verify the parts are all the same length
	var firstPartLen int
	for x := range parts {
		firstPartLen = len(parts[x])
		break
	}
	if firstPartLen < 1 {
		return nil, fmt.Errorf("parts must be at least one uint16 long")
	}
	for _, part := range parts {
		if len(part) != firstPartLen {
			return nil, fmt.Errorf("all parts must be the same length")
		}
	}

	// Create a buffer to store the reconstructed secret
	secret := make([]uint16, firstPartLen)
	points := make([]pair, len(parts))

	for i := range secret {
		p := 0
		for k, v := range parts {
			points[p] = pair{x: k, y: v[i]}
			p++
		}
		secret[i] = f.interpolate(points, 0)
	}

	return secret, nil
}

func (f *Field) CombineUniqueX(parts []PriShare) ([]uint16, error) {
	// fmt.Println(parts)
	// Verify enough parts provided
	if len(parts) < 2 {
		return nil, fmt.Errorf("less than two parts cannot be used to reconstruct the secret")
	}

	// Verify the parts are all the same length
	firstPartLen := len(parts[0].Y)
	// fmt.Println(firstPartLen)

	if firstPartLen < 1 {
		return nil, fmt.Errorf("parts must be at least one uint16 long")
	}
	for _, part := range parts {
		if len(part.Y) != firstPartLen {
			return nil, fmt.Errorf("all parts must be the same length")
		}
	}

	// Create a buffer to store the reconstructed secret
	secret := make([]uint16, firstPartLen)
	points := make([]pair, len(parts))

	for i := range secret {
		p := 0
		for _, val := range parts {
			points[p] = pair{x: val.X, y: val.Y[i]}
			p++
		}
		// fmt.Println(points)
		secret[i] = f.interpolate(points, 0)
	}
	// fmt.Println(secret)

	return secret, nil
}
