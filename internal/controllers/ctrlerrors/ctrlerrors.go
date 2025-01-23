package ctrlerrors

import "fmt"

// Error represents an error that can be returned by a controller.
type Error struct {
	InternalError error
	ExternalMsg   string
	Code          int
}

func (e Error) Error() string {
	return fmt.Sprintf("%s: %s", e.ExternalMsg, e.InternalError)
}

func (e Error) Unwrap() error {
	return e.InternalError
}
