//go:build android

package net

func newPlatformControlPlaneResolver(dialer contextDialer) hostResolver {
	return newPublicFallbackResolver(dialer)
}
