package pamrolebinding

import (
	"context"
	"sync"
)

// FakeGrantLister is an in-memory GrantLister for tests.
type FakeGrantLister struct {
	mu     sync.Mutex
	grants map[string][]Grant
	errs   map[string]error
	calls  map[string]int
	during func()
}

// SetDuringList sets a function to run inside every ListActiveGrants call, e.g. to move
// a fake clock forward as if PAM were slow to answer. nil clears it.
func (f *FakeGrantLister) SetDuringList(fn func()) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.during = fn
}

func NewFakeGrantLister() *FakeGrantLister {
	return &FakeGrantLister{grants: map[string][]Grant{}, errs: map[string]error{}, calls: map[string]int{}}
}

// SetGrants replaces the active grants on an entitlement, and clears any error.
func (f *FakeGrantLister) SetGrants(entitlement string, grants ...Grant) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.grants[entitlement] = grants
	delete(f.errs, entitlement)
}

// SetError makes listing an entitlement's grants fail.
func (f *FakeGrantLister) SetError(entitlement string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.errs[entitlement] = err
}

// Calls returns how many times an entitlement's grants have been listed.
func (f *FakeGrantLister) Calls(entitlement string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[entitlement]
}

func (f *FakeGrantLister) ListActiveGrants(_ context.Context, entitlement string) ([]Grant, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls[entitlement]++
	if f.during != nil {
		f.during()
	}
	if err, ok := f.errs[entitlement]; ok {
		return nil, err
	}
	grants, ok := f.grants[entitlement]
	if !ok {
		return nil, ErrEntitlementNotFound
	}
	return append([]Grant{}, grants...), nil
}
