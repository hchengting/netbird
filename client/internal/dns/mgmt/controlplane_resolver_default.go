//go:build !android

package mgmt

func newPlatformControlPlaneResolver() hostResolver {
	return nil
}
