package context

import (
	"context"
	"sync"
	"time"
)

type CtxKey string

type Context struct {
	data map[any]any
	ctx  context.Context
	mu   sync.RWMutex
}

func (c *Context) Set(key any, value any) {
	c.mu.Lock()

	defer c.mu.Unlock()

	c.data[key] = value
}

func (c *Context) Deadline() (deadline time.Time, ok bool) {
	return c.ctx.Deadline()
}

func (c *Context) Done() <-chan struct{} {
	return c.ctx.Done()
}

func (c *Context) Err() error {
	return c.ctx.Err()
}

func (c *Context) Value(key any) any {
	c.mu.RLock()

	defer c.mu.RUnlock()

	return c.data[key]
}

func (c *Context) Copy() *Context {
	c.mu.RLock()

	defer c.mu.RUnlock()

	newData := make(map[any]any, len(c.data))
	for key, value := range c.data {
		newData[key] = value
	}

	return &Context{
		data: newData,
		ctx:  c.ctx,
	}
}

// NewContext creates and initializes a new Context instance with an empty data map and a background context.
func NewContext() *Context {
	return &Context{
		data: make(map[any]any),
		ctx:  context.Background(),
	}
}
