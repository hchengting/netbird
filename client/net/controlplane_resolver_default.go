//go:build !android

package net

func newPlatformControlPlaneResolver() hostResolver {
	return nil
}
