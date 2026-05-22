// Package state owns Redis-backed affinity, session and runtime state boundaries.
package state

import "github.com/redis/go-redis/v9"

// RedisClient is the narrow Redis command boundary shared by state components.
type RedisClient interface {
	redis.Cmdable
}
