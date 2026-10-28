//go:build cgo && windows && amd64

package leanpq

// #cgo LDFLAGS: -L${SRCDIR}/internal/native/windows_amd64 -llean_pq_native -lkernel32 -lntdll -luserenv -lws2_32 -ldbghelp
import "C"
