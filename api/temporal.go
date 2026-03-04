package main

import (
	"go.temporal.io/sdk/client"
)

var tc client.Client

func initTemporal(address string) error {
	var err error
	tc, err = client.Dial(client.Options{
		HostPort: address,
	})
	return err
}

func closeTemporal() {
	if tc != nil {
		tc.Close()
	}
}
