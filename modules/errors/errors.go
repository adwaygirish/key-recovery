package errors

import "errors"

// Custom errors used across the repository
var (
	ErrBytesNotEqual       = errors.New("byte slices not equal")
	ErrPacketsNotGenerated = errors.New("error in generating packets")
	ErrInvalidThreshold    = errors.New("threshold is more than the number of shares")
	ErrVeryLargeThreshold  = errors.New("threshold is more than the system requirement")
	ErrInvalidInput        = errors.New("invalid input")
	ErrNoOfSharesNotEqual  = errors.New("no. of shares are not equal in the two packets")
	ErrMarkerNoMatch       = errors.New("no marker info matches from the obtained secret")
	ErrSecretNotFound      = errors.New("secret could not be found with any of the combinations")
	ErrInvalidSliceLength  = errors.New("length of the slices do not match")
)
