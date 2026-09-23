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

package state

import (
	"strconv"
	"strings"
	"sync"
)

const (
	// redisClusterSlots is the fixed Redis Cluster hash-slot space.
	redisClusterSlots = 16384
	// spreadHashTagSearchLimit bounds the deterministic tag search; CRC16 reaches every interval long before.
	spreadHashTagSearchLimit = 1 << 20
)

// redisClusterSlot returns the Redis Cluster hash slot of a key, honoring the first non-empty hash tag.
func redisClusterSlot(key string) int {
	return int(redisCRC16(redisClusterHashInput(key)) % redisClusterSlots)
}

// redisClusterHashTag returns the Cluster hash input of a key and whether it came from a hash tag.
func redisClusterHashTag(key string) (string, bool) {
	start := strings.IndexByte(key, '{')
	if start < 0 {
		return key, false
	}

	end := strings.IndexByte(key[start+1:], '}')
	if end <= 0 {
		return key, false
	}

	return key[start+1 : start+1+end], true
}

// redisClusterHashInput returns the exact byte sequence Redis Cluster hashes for a key.
func redisClusterHashInput(key string) string {
	input, _ := redisClusterHashTag(key)

	return input
}

// redisCRC16 implements the CRC16-CCITT (XMODEM) variant used by Redis Cluster.
func redisCRC16(value string) uint16 {
	crc := uint16(0)

	for index := range len(value) {
		crc ^= uint16(value[index]) << 8

		for range 8 {
			if crc&0x8000 != 0 {
				crc = (crc << 1) ^ 0x1021
			} else {
				crc <<= 1
			}
		}
	}

	return crc
}

// spreadHashTag returns the deterministic hash tag for one bucket of a key family.
//
// The tag's Cluster slot lies inside the bucket's equal share of the slot space.
// Bucket families therefore spread evenly across masters that own contiguous,
// equally sized slot ranges, independent of CRC16 luck for short sequential
// names. The result is a pure function of family, bucket and bucket count and
// is part of the persisted key contract.
func spreadHashTag(family string, bucket int, buckets int) (string, error) {
	if buckets <= 0 || buckets > redisClusterSlots || bucket < 0 || bucket >= buckets || strings.ContainsAny(family, "{}") {
		return "", newStateError(RedisErrorKindConfig, "keys", "invalid hash-tag bucket family", nil)
	}

	low := (bucket*redisClusterSlots + buckets - 1) / buckets
	high := ((bucket + 1) * redisClusterSlots) / buckets
	base := family + ":" + twoDigit(bucket) + "."

	for nonce := range spreadHashTagSearchLimit {
		tag := base + strconv.Itoa(nonce)

		slot := int(redisCRC16(tag) % redisClusterSlots)
		if slot >= low && slot < high {
			return "{" + tag + "}", nil
		}
	}

	return "", newStateError(RedisErrorKindConfig, "keys", "no hash tag found for bucket slot range", nil)
}

// twoDigit formats a bucket number with the stable two-digit width used in key names.
func twoDigit(value int) string {
	if value >= 0 && value < 10 {
		return "0" + strconv.Itoa(value)
	}

	return strconv.Itoa(value)
}

// spreadHashTagCache memoizes per-family bucket tags that are expensive enough to search once.
type spreadHashTagCache struct {
	tags sync.Map
}

// bucketTags returns the memoized tags for every bucket of one family.
func (c *spreadHashTagCache) bucketTags(family string, buckets int) ([]string, error) {
	if cached, ok := c.tags.Load(family); ok {
		if tags, valid := cached.([]string); valid && len(tags) == buckets {
			return tags, nil
		}
	}

	tags := make([]string, buckets)

	for bucket := range buckets {
		tag, err := spreadHashTag(family, bucket, buckets)
		if err != nil {
			return nil, err
		}

		tags[bucket] = tag
	}

	actual, _ := c.tags.LoadOrStore(family, tags)
	if stored, ok := actual.([]string); ok && len(stored) == buckets {
		return stored, nil
	}

	return tags, nil
}
