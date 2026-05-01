package rotauth

import "errors"

var (
	errNoToken      = errors.New("rotauth: no access token available")
	errNotSupported = errors.New("rotauth: not supported")
)
