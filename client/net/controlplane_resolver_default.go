//go:build !android

package net

func newPlatformControlPlaneResolver(contextDialer) hostResolver {
	return nil
}
