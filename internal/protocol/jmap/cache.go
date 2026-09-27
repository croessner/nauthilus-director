// Copyright (C) 2026 Christian Rößner
//
// SPDX-License-Identifier: AGPL-3.0-only
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, version 3 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package jmap

import (
	"container/list"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"hash"
	"sync"
	"time"
)

const cacheKeyBytes = 32

// cacheKey is the HMAC of one credential and client address; the credential itself is never stored.
type cacheKey [sha256.Size]byte

// authCache is a bounded, process-local LRU of successful authentication results.
//
// Entries are keyed by an HMAC under a random per-process key, so neither the credential nor a
// reusable digest of it is kept in memory. Only successful results are cached: a rejected or
// temporarily failed credential always reaches the authority again. The client address is part of
// the key so that authority policies bound to the client address see every new address.
type authCache struct {
	mu         sync.Mutex
	secret     []byte
	ttl        time.Duration
	maxEntries int
	now        func() time.Time
	order      *list.List
	entries    map[cacheKey]*list.Element
}

// authCacheEntry is one cached principal with its absolute expiry.
type authCacheEntry struct {
	key       cacheKey
	principal principal
	expires   time.Time
}

// newAuthCache creates an empty cache with a fresh random HMAC key.
func newAuthCache(ttl time.Duration, maxEntries int, now func() time.Time) (*authCache, error) {
	if ttl <= 0 || maxEntries <= 0 {
		return nil, errors.New("jmap: auth cache ttl and size must be positive")
	}

	secret := make([]byte, cacheKeyBytes)
	if _, err := rand.Read(secret); err != nil {
		return nil, errors.New("jmap: create auth cache key")
	}

	if now == nil {
		now = time.Now
	}

	return &authCache{
		secret:     secret,
		ttl:        ttl,
		maxEntries: maxEntries,
		now:        now,
		order:      list.New(),
		entries:    map[cacheKey]*list.Element{},
	}, nil
}

// key derives the cache key of one credential as seen from one client address.
func (c *authCache) key(cred credential, clientIP string) cacheKey {
	mac := hmac.New(sha256.New, c.secret)
	writeKeyPart(mac, cred.scheme)
	writeKeyPart(mac, cred.username)
	writeKeyPart(mac, cred.secret.Value())
	writeKeyPart(mac, clientIP)

	var key cacheKey

	copy(key[:], mac.Sum(nil))

	return key
}

// writeKeyPart feeds one length-delimited field into the HMAC so fields cannot shift into each other.
func writeKeyPart(mac hash.Hash, value string) {
	length := len(value)
	_, _ = mac.Write([]byte{byte(length >> 24), byte(length >> 16), byte(length >> 8), byte(length)})
	_, _ = mac.Write([]byte(value))
}

// get returns a detached copy of a live entry and refreshes its recency.
func (c *authCache) get(key cacheKey) (principal, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	element, ok := c.entries[key]
	if !ok {
		return principal{}, false
	}

	entry, _ := element.Value.(*authCacheEntry)
	if entry == nil || !c.now().Before(entry.expires) {
		c.removeLocked(element)

		return principal{}, false
	}

	c.order.MoveToFront(element)

	return entry.principal.clone(), true
}

// put stores one successful principal, evicting expired and then least recently used entries.
func (c *authCache) put(key cacheKey, value principal) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.now()
	if element, ok := c.entries[key]; ok {
		c.removeLocked(element)
	}

	for c.order.Len() >= c.maxEntries {
		oldest := c.order.Back()
		if oldest == nil {
			break
		}

		c.removeLocked(oldest)
	}

	entry := &authCacheEntry{key: key, principal: value.clone(), expires: now.Add(c.ttl)}
	c.entries[key] = c.order.PushFront(entry)
}

// len reports the number of stored entries, including not yet evicted expired ones.
func (c *authCache) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.order.Len()
}

// removeLocked drops one element while c.mu is held.
func (c *authCache) removeLocked(element *list.Element) {
	if entry, ok := element.Value.(*authCacheEntry); ok && entry != nil {
		delete(c.entries, entry.key)
	}

	c.order.Remove(element)
}

// clone detaches mutable attribute slices of one principal.
func (p principal) clone() principal {
	p.attributes = cloneAttributes(p.attributes)

	return p
}
