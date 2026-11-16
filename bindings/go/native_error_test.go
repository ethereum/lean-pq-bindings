package leanpq

import (
	"fmt"
	"runtime"
	"strings"
	"sync"
	"testing"
)

// The native bridge keeps the message of the last failed call in a thread-local and hands it out
// through a second call. A goroutine can move to another OS thread between the two calls, and
// then it reads the message of whatever call that thread ran last, or none at all.
//
// Every failing leanXMSS verification names the leaf index of its signature, so a goroutine that
// verifies a signature made at its own leaf index must see exactly that number in the error.
// Other goroutines run successful verifications at the same time, because a success clears the
// thread's message.
func TestNativeErrorsBelongToTheirCall(t *testing.T) {
	const (
		failers    = 24
		succeeders = 8
		rounds     = 200
	)
	previous := runtime.GOMAXPROCS(8)
	defer runtime.GOMAXPROCS(previous)

	key := mustXmssKey(t, bytes32(21))
	publicKey := mustXmssPublicKey(t, key)
	message := bytes32(0x51)
	other := bytes32(0x52)

	signatures := make([]XmssSignature, failers+succeeders)
	for leaf := range signatures {
		signature, err := key.Sign(message, uint32(leaf))
		if err != nil {
			t.Fatal(err)
		}
		signatures[leaf] = signature
	}

	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		problems []string
	)
	report := func(format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		if len(problems) < 5 {
			problems = append(problems, fmt.Sprintf(format, args...))
		}
	}

	for leaf := 0; leaf < failers; leaf++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			want := fmt.Sprintf("leaf index %d ", leaf)
			for round := 0; round < rounds; round++ {
				err := XmssVerify(publicKey, other, signatures[leaf])
				switch {
				case err == nil:
					report("leaf %d: verification of the wrong message succeeded", leaf)
					return
				case strings.Contains(err.Error(), "native operation failed with status"):
					report("leaf %d: the native message was lost: %v", leaf, err)
				case !strings.Contains(err.Error(), want):
					report("leaf %d: got another call's message: %v", leaf, err)
				}
			}
		}()
	}
	for leaf := failers; leaf < failers+succeeders; leaf++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for round := 0; round < rounds; round++ {
				if err := XmssVerify(publicKey, message, signatures[leaf]); err != nil {
					report("leaf %d: a valid signature was rejected: %v", leaf, err)
					return
				}
			}
		}()
	}
	wg.Wait()

	if len(problems) > 0 {
		t.Fatalf("native errors crossed between goroutines:\n%s", strings.Join(problems, "\n"))
	}
}
