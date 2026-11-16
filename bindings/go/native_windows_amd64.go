//go:build cgo && windows && amd64

package leanpq

// The Rust standard library's imports (`--print native-static-libs`), plus `synchronization`:
// MinGW's ld scans the archive once, and the `WaitOnAddress` import stubs Rust embeds can land
// before the leanVM objects that reference them.
//
// #cgo LDFLAGS: -L${SRCDIR}/internal/native/windows_amd64 -llean_pq_native -lkernel32 -lntdll -luserenv -lws2_32 -ldbghelp -lsynchronization
import "C"
