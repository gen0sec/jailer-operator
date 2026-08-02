// Package roleid maps an effective policy to the numeric role id jailer uses.
//
// The id is derived from the policy's fingerprint rather than handed out in
// sequence, so a restarted controller re-derives the same ids and does not
// re-enroll every pod on the cluster. Collisions probe to the next free slot.
package roleid

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sync"
)

// DefaultCapacity mirrors the role_flags map's max_entries in the engine.
// Allocating beyond it would produce a role the kernel cannot hold.
const DefaultCapacity uint32 = 1024

// Allocator hands out role ids and remembers which fingerprint owns each.
type Allocator struct {
	mu            sync.Mutex
	capacity      uint32
	byFingerprint map[string]uint32
	owner         map[uint32]string
}

func New(capacity uint32) *Allocator {
	if capacity == 0 {
		capacity = DefaultCapacity
	}
	return &Allocator{
		capacity:      capacity,
		byFingerprint: make(map[string]uint32),
		owner:         make(map[uint32]string),
	}
}

// slot maps a fingerprint into [1, capacity]. Zero is reserved: it is what an
// unenrolled task carries, so an enrolled pod holding it would be
// indistinguishable from one that was never enrolled.
func (a *Allocator) slot(fingerprint string, probe uint32) uint32 {
	sum := sha256.Sum256([]byte(fingerprint))
	base := binary.BigEndian.Uint64(sum[:8])
	return uint32((base+uint64(probe))%uint64(a.capacity)) + 1
}

// Allocate returns the id for a fingerprint, assigning one if needed.
func (a *Allocator) Allocate(fingerprint string) (uint32, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if id, ok := a.byFingerprint[fingerprint]; ok {
		return id, nil
	}
	for probe := uint32(0); probe < a.capacity; probe++ {
		id := a.slot(fingerprint, probe)
		if _, taken := a.owner[id]; !taken {
			a.byFingerprint[fingerprint] = id
			a.owner[id] = fingerprint
			return id, nil
		}
	}
	// Wrapping to an in-use id would give one policy another's rules.
	return 0, fmt.Errorf(
		"no free role id: all %d are in use, which is the engine's role_flags capacity",
		a.capacity)
}

// Release gives an id back so a policy that no longer matches any pod does not
// hold a slot forever.
func (a *Allocator) Release(fingerprint string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if id, ok := a.byFingerprint[fingerprint]; ok {
		delete(a.byFingerprint, fingerprint)
		delete(a.owner, id)
	}
}
