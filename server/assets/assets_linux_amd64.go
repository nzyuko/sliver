//go:build server

package assets

import "embed"

var (
	//go:embed fs/sliver.asc fs/libreflect.a fs/*.txt fs/*.zip fs/linux/amd64/*
	assetsFs embed.FS
)
