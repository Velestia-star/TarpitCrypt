package main

// 默认占位：通用启动器只用于 v1–v3，v4 需构建时生成派生函数。
func init() {
	keyFn = func(packs []Pack) []byte { return nil }
}
