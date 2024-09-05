package shamir

import (
	"bytes"
	"fmt"
	"testing"
)

func TestMult(t *testing.T) {
	testCases := []struct {
		a        uint16
		b        uint16
		expected uint16
	}{
		{uint16(2), uint16(3), uint16(6)},
	}
	var f Field
	f.InitializeTables()

	for _, tc := range testCases {
		prod := f.Mult(tc.a, tc.b)
		if prod != tc.expected {
			t.Error("Wrong product for", tc.a, tc.b, tc.expected, prod)
		}
	}
}

func TestSplit(t *testing.T) {
	secret := []byte("testbestaa")
	secret16 := KeyBytesToKeyUint16s(secret)
	fmt.Println(secret16)

	var f Field

	f.InitializeTables()

	out, ps, err := f.Split(secret16, 5, 3)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if len(out) != 5 {
		t.Fatalf("bad: %v", out)
	}

	for _, share := range out {
		if len(share) != len(secret16) {
			t.Fatalf("bad: %v", out)
		}
	}

	for o, val := range out {
		for i, p := range ps {
			eval := f.evaluate(o, p)
			if eval != val[i] {
				fmt.Println("wrong")
			}
		}
	}

}

func TestInterpolate(t *testing.T) {
	var f Field
	f.InitializeTables()
	intercept := uint16(1)
	degree := uint16(2)
	p, err := makePolynomial(intercept, degree)
	fmt.Println(p)
	if err != nil {
		t.Error(err)
	}
	fmt.Println(f.evaluate(uint16(1), p))
	points := make([]pair, 0)
	for i := 0; i < 3; i++ {
		// vals.append(p.evaluate(i+1))
		points = append(points, pair{x: uint16(i + 1), y: f.evaluate(uint16(i+1), p)})
		fmt.Println(f.evaluate(uint16(i+1), p))
	}

	interpolatedIntercept := f.interpolate(points, 0)

	fmt.Println(interpolatedIntercept, intercept)
}

func TestCombine(t *testing.T) {
	var f Field
	secret := []byte("testbesta")
	secret16 := KeyBytesToKeyUint16s(secret)
	fmt.Println(secret16)

	f.InitializeTables()

	out, ps, err := f.Split(secret16, 5, 3)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	for o, val := range out {
		for i, p := range ps {
			eval := f.evaluate(o, p)
			if eval != val[i] {
				fmt.Println("wrong")
			}
		}
	}

	keys := make([]uint16, len(out))

	i := 0
	for k := range out {
		keys[i] = k
		i++
	}

	// There is 5*4*3 possible choices,
	// we will just brute force try them all
	for i := uint16(0); i < 5; i++ {
		for j := uint16(0); j < 5; j++ {
			if j == i {
				continue
			}
			for k := uint16(0); k < 5; k++ {
				if k == i || k == j {
					continue
				}
				parts := map[uint16][]uint16{
					keys[i]: out[keys[i]],
					keys[j]: out[keys[j]],
					keys[k]: out[keys[k]],
				}
				recomb, err := f.Combine(parts)
				if err != nil {
					t.Fatalf("err: %v", err)
				}

				recombBytes := KeyUint16sToKeyBytes(recomb)

				if !bytes.Equal(recombBytes, secret) {
					t.Errorf("parts: (i:%d, j:%d, k:%d) %v", i, j, k, parts)
					t.Fatalf("bad: %v %v", recombBytes, secret)
				}
			}
		}
	}
}
