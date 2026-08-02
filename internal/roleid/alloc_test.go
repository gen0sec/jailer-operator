package roleid

import (
	"fmt"
	"strings"
	"testing"
)

func TestTheSameFingerprintAlwaysGetsTheSameID(t *testing.T) {
	a := New(DefaultCapacity)
	first, err := a.Allocate("abc")
	if err != nil {
		t.Fatal(err)
	}
	second, err := a.Allocate("abc")
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Errorf("id churned for an unchanged policy: %d then %d", first, second)
	}
}

func TestDifferentFingerprintsGetDifferentIDs(t *testing.T) {
	a := New(DefaultCapacity)
	x, _ := a.Allocate("one")
	y, err := a.Allocate("two")
	if err != nil {
		t.Fatal(err)
	}
	if x == y {
		t.Errorf("two policies share id %d, so one would enforce the other's rules", x)
	}
}

// role 0 is what an unenrolled task carries, so handing it out would make an
// enrolled pod indistinguishable from one that was never enrolled.
func TestZeroIsNeverAllocated(t *testing.T) {
	a := New(DefaultCapacity)
	for i := range 200 {
		id, err := a.Allocate(fmt.Sprintf("fp-%d", i))
		if err != nil {
			t.Fatal(err)
		}
		if id == 0 {
			t.Fatal("allocated 0")
		}
	}
}

func TestIDsStayWithinTheEnginesMapCapacity(t *testing.T) {
	a := New(DefaultCapacity)
	for i := range 500 {
		id, err := a.Allocate(fmt.Sprintf("fp-%d", i))
		if err != nil {
			t.Fatal(err)
		}
		if id > DefaultCapacity {
			t.Fatalf("id %d exceeds the role_flags capacity %d", id, DefaultCapacity)
		}
	}
}

// Colliding derived slots must probe to a free one, keeping both policies
// distinct rather than letting the later overwrite the earlier.
func TestCollisionsResolveWithoutLosingAPolicy(t *testing.T) {
	a := New(4) // tiny space forces collisions
	seen := map[uint32]string{}
	for _, fp := range []string{"a", "b", "c"} {
		id, err := a.Allocate(fp)
		if err != nil {
			t.Fatalf("%s: %v", fp, err)
		}
		if other, taken := seen[id]; taken {
			t.Fatalf("%s got id %d already held by %s", fp, id, other)
		}
		seen[id] = fp
	}
}

// Running out must be an error the operator can report, not a wrapped id that
// silently gives one policy another's rules.
func TestExhaustionIsAnError(t *testing.T) {
	a := New(2)
	var err error
	for i := range 10 {
		if _, err = a.Allocate(fmt.Sprintf("fp-%d", i)); err != nil {
			break
		}
	}
	if err == nil {
		t.Fatal("want an error once the id space is full")
	}
	if !strings.Contains(err.Error(), "2") {
		t.Errorf("the error should state the limit, got %q", err)
	}
}

func TestReleasedIDsAreReusable(t *testing.T) {
	a := New(2)
	if _, err := a.Allocate("a"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Allocate("b"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Allocate("c"); err == nil {
		t.Fatal("expected exhaustion")
	}
	a.Release("a")
	if _, err := a.Allocate("c"); err != nil {
		t.Errorf("after releasing, an id should be available: %v", err)
	}
}

// A restarted controller re-derives ids from the same fingerprints; if that
// produced different ids, every pod would be re-enrolled after a restart.
func TestAFreshAllocatorDerivesTheSameIDs(t *testing.T) {
	fps := []string{"alpha", "beta", "gamma"}
	first := map[string]uint32{}
	a := New(DefaultCapacity)
	for _, fp := range fps {
		id, _ := a.Allocate(fp)
		first[fp] = id
	}
	b := New(DefaultCapacity)
	for _, fp := range fps {
		id, _ := b.Allocate(fp)
		if id != first[fp] {
			t.Errorf("%s: %d after restart, was %d", fp, id, first[fp])
		}
	}
}
