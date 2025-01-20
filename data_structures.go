// SPDX-FileCopyrightText: 2024 - 2025 Mass Labs
//
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"fmt"
)

func subslice[T any](original []T, subsliceSize int) [][]T {
	subsliced := make([][]T, 0)
	for s := 0; s*subsliceSize < len(original); s++ {
		start := s * subsliceSize
		end := (s + 1) * subsliceSize
		if end > len(original) {
			end = len(original)
		}
		part := original[start:end]
		subsliced = append(subsliced, part)
	}
	return subsliced
}

// Data structures are defined here only if we can't make standard generic data
// structures (like Maps or Sets) and associated methods because our `id`s are
// not handled as expected by Go maps, as `id`s are slices.
// Data structures or functionality that is specific to a particular piece of
// server functionality should be defined next to that functionality or just
// inline.

// Use a sentinel instead of a bool to save one byte of space per map value.
var exists = struct{}{}

// SetInts is a set of requestIDs.
type SetInts[K comparable] struct {
	elems map[K]struct{}
}

// NewSetInts creates a new set of requestIDs.
func NewSetInts[K comparable](ids ...K) *SetInts[K] {
	s := &SetInts[K]{}
	s.Clear(uint(len(ids)))
	for _, id := range ids {
		s.Add(id)
	}
	return s
}

// Clear the set.
func (s *SetInts[K]) Clear(size uint) {
	s.elems = make(map[K]struct{}, size)
}

// Has returns true if the set contains the given requestID.
func (s *SetInts[K]) Has(e K) bool {
	_, ok := s.elems[e]
	return ok
}

// Add a requestID to the set.
func (s *SetInts[K]) Add(e K) {
	s.elems[e] = exists
}

// Merge the set with another set.
func (s *SetInts[K]) Merge(other *SetInts[K]) {
	assert(s != other)
	for k := range other.elems {
		s.elems[k] = exists
	}
}

// Delete a requestID from the set.
func (s *SetInts[K]) Delete(e K) {
	delete(s.elems, e)
}

// All calls the given function for each requestID in the set.
// Returning true halts the iteration
func (s *SetInts[K]) All(f func(K) bool) {
	for e := range s.elems {
		if f(e) {
			break
		}
	}
}

// Slice create a copy of the set as a slice.
//
//revive:disable:unexported-return
func (s *SetInts[K]) Slice() []K {
	sz := s.Size()
	slice := make([]K, sz)
	i := 0
	for e := range s.elems {
		slice[i] = e
		i++
	}
	return slice
}

// Size returns the number of requestIDs in the set.
func (s *SetInts[K]) Size() int {
	return len(s.elems)
}

// Intersection returns a new set that contains the intersection of the two sets.
func (s *SetInts[K]) Intersection(other *SetInts[K]) *SetInts[K] {
	var it = NewSetInts[K]()
	s.All(func(i K) bool {
		if other.Has(i) {
			it.Add(i)
		}
		return false
	})
	other.All(func(i K) bool {
		if s.Has(i) {
			it.Add(i)
		}
		return false
	})
	return it
}

// MapInts is a map from requestIDs to values.
type MapInts[K comparable, V any] struct {
	elems map[K]V
}

// NewMapInts creates a new map from requestIDs to values.
func NewMapInts[K comparable, V any]() *MapInts[K, V] {
	m := &MapInts[K, V]{}
	m.Clear()
	return m
}

// Clear the map.
func (m *MapInts[K, V]) Clear() {
	m.elems = make(map[K]V)
}

// Has returns true if the map contains the given requestID.
func (m *MapInts[K, V]) Has(k K) bool {
	_, ok := m.elems[k]
	return ok
}

// GetHas returns the value and true if the map contains the given requestID.
func (m *MapInts[K, V]) GetHas(k K) (V, bool) {
	v, has := m.elems[k]
	return v, has
}

// Get returns the value for the given requestID.
func (m *MapInts[K, V]) Get(k K) V {
	return m.elems[k]
}

// GetOrCreate returns the value for the given requestID, creating it if it doesn't exist.
func (m *MapInts[K, V]) GetOrCreate(k K, f func(K) V) V {
	v, has := m.GetHas(k)
	if !has {
		v = f(k)
		m.Set(k, v)
	}
	return v
}

// MustGet returns the value for the given requestID, panicking if it doesn't exist.
func (m *MapInts[K, V]) MustGet(k K) V {
	v, has := m.elems[k]
	assertWithMessage(has, fmt.Sprintf("element %v missing in set", k))
	return v
}

// Set the value for the given requestID.
func (m *MapInts[K, V]) Set(k K, v V) {
	m.elems[k] = v
}

// Delete the value for the given requestID.
func (m *MapInts[K, V]) Delete(k K) {
	delete(m.elems, k)
}

// Keys returns a slice of all the requestIDs in the map.
func (m *MapInts[K, V]) Keys() []K {
	keys := make([]K, len(m.elems))
	i := 0
	for k := range m.elems {
		keys[i] = k
		i++
	}
	return keys
}

// All calls the given function for each requestID and value in the map.
// returning true halts the iteration
func (m *MapInts[K, V]) All(f func(K, V) bool) {
	for k, v := range m.elems {
		if f(k, v) {
			break
		}
	}
}

// AllValues calls the given function for each value in the map.
func (m *MapInts[K, V]) AllValues(f func(V)) {
	for _, v := range m.elems {
		f(v)
	}
}

// Find calls the given function for each key and value in the map and returns the first requestID and value for which the function returns true.
func (m *MapInts[K, V]) Find(check func(K, V) bool) (K, bool) {
	for k, v := range m.elems {
		if check(k, v) {
			return k, true
		}
	}
	var zero K
	return zero, false
}

// Size returns the number of requestIDs in the map.
func (m *MapInts[K, V]) Size() int {
	return len(m.elems)
}

// ShopObjectIDArray is a 16 byte array.
type ShopObjectIDArray [16]byte

// ShopEventMap is a map from requestIDs to values.
type ShopEventMap[V any] struct {
	elems map[ShopObjectIDArray]V
}

// NewShopEventMap creates a new map from requestIDs to values.
func NewShopEventMap[V any]() *ShopEventMap[V] {
	m := &ShopEventMap[V]{}
	m.Clear()
	return m
}

// Clear the map.
func (m *ShopEventMap[V]) Clear() {
	m.elems = make(map[ShopObjectIDArray]V)
}

// Has returns true if the map contains the given requestID.
func (m *ShopEventMap[V]) Has(k ShopObjectIDArray) bool {
	_, ok := m.elems[k]
	return ok
}

// GetHas returns the value and true if the map contains the given requestID.
func (m *ShopEventMap[V]) GetHas(k ShopObjectIDArray) (V, bool) {
	v, has := m.elems[k]
	return v, has
}

// Get returns the value for the given requestID.
func (m *ShopEventMap[V]) Get(k ShopObjectIDArray) V {
	return m.elems[k]
}

// GetOrCreate returns the value for the given requestID, creating it if it doesn't exist.
func (m *ShopEventMap[V]) GetOrCreate(k ShopObjectIDArray, f func(ShopObjectIDArray) V) V {
	v, has := m.GetHas(k)
	if !has {
		v = f(k)
		m.Set(k, v)
	}
	return v
}

// MustGet returns the value for the given requestID, panicking if it doesn't exist.
func (m *ShopEventMap[V]) MustGet(k ShopObjectIDArray) V {
	v, has := m.elems[k]
	assertWithMessage(has, fmt.Sprintf("element %v missing in set", k))
	return v
}

// Set the value for the given requestID.
func (m *ShopEventMap[V]) Set(k ShopObjectIDArray, v V) {
	m.elems[k] = v
}

// Delete the value for the given requestID.
func (m *ShopEventMap[V]) Delete(k ShopObjectIDArray) {
	delete(m.elems, k)
}

// Keys returns a slice of all the requestIDs in the map.
func (m *ShopEventMap[V]) Keys() []ShopObjectIDArray {
	keys := make([]ShopObjectIDArray, len(m.elems))
	i := 0
	for k := range m.elems {
		keys[i] = k
		i++
	}
	return keys
}

// All calls the given function for each requestID and value in the map.
// returning true halts the iteration
func (m *ShopEventMap[V]) All(f func(ShopObjectIDArray, V) bool) {
	for k, v := range m.elems {
		if f(k, v) {
			break
		}
	}
}

// AllValues calls the given function for each value in the map.
func (m *ShopEventMap[V]) AllValues(f func(V)) {
	for _, v := range m.elems {
		f(v)
	}
}

// Find calls the given function for each key and value in the map and returns the first requestID and value for which the function returns true.
func (m *ShopEventMap[V]) Find(check func(ShopObjectIDArray, V) bool) (ShopObjectIDArray, bool) {
	for k, v := range m.elems {
		if check(k, v) {
			return k, true
		}
	}
	var zero ShopObjectIDArray
	return zero, false
}

// Size returns the number of requestIDs in the map.
func (m *ShopEventMap[V]) Size() int {
	return len(m.elems)
}

//revive:enable:unexported-return
