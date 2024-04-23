// SPDX-FileCopyrightText: 2024 Mass Labs
//
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import "bytes"

// Data structures are defined here only if we can't make standard generic data
// structures (like Maps or Sets) and associated methods because our `id`s are
// not handled as expected by Go maps, as `id`s are slices.
// Data structures or functionality that is specific to a particular piece of
// server functionality should be defined next to that functionality or just
// inline.

type eventIDSlice []eventID

func (ids eventIDSlice) has(x eventID) bool {
	for _, i := range ids {
		if i.Equal(x) {
			return true
		}
	}
	return false
}

func (ids eventIDSlice) subslice(subsliceSize int) [][]eventID {
	subsliced := make([][]eventID, 0)
	for s := 0; s*subsliceSize < len(ids); s++ {
		start := s * subsliceSize
		end := (s + 1) * subsliceSize
		if end > len(ids) {
			end = len(ids)
		}
		part := ids[start:end]
		subsliced = append(subsliced, part)
	}
	return subsliced
}

func (ids eventIDSlice) Len() int {
	return len(ids)
}

func (ids eventIDSlice) Less(a, b int) bool {
	return bytes.Compare(ids[a], ids[b]) == -1
}

func (ids eventIDSlice) Swap(a, b int) {
	ids[a], ids[b] = ids[b], ids[a]
}

type requestIDSlice []requestID

func (ids requestIDSlice) has(x requestID) bool {
	for _, i := range ids {
		if i.Equal(x) {
			return true
		}
	}
	return false
}

func (ids requestIDSlice) subslice(subsliceSize int) [][]requestID {
	subsliced := make([][]requestID, 0)
	for s := 0; s*subsliceSize < len(ids); s++ {
		start := s * subsliceSize
		end := (s + 1) * subsliceSize
		if end > len(ids) {
			end = len(ids)
		}
		part := ids[start:end]
		subsliced = append(subsliced, part)
	}
	return subsliced
}

// Represent ids as arrays internally so that they work with Go maps.
type requestIDByteArray [requestIDBytes]byte

func requestIDToBytes(id requestID) requestIDByteArray {
	var bytes requestIDByteArray
	copy(bytes[:], id)
	return bytes
}

func bytesToRequestID(bytes requestIDByteArray) requestID {
	return bytes[:]
}

// Use a sentinel instead of a bool to save one byte of space per map value.
var exists = struct{}{}

// SetRequestIDs is a set of requestIDs.
type SetRequestIDs struct {
	elems map[requestIDByteArray]struct{}
}

// NewSetRequestIDs creates a new set of requestIDs.
func NewSetRequestIDs(ids ...requestID) *SetRequestIDs {
	s := &SetRequestIDs{}
	s.Clear(uint(len(ids)))
	for _, id := range ids {
		s.Add(id)
	}
	return s
}

// Clear the set.
func (s *SetRequestIDs) Clear(size uint) {
	s.elems = make(map[requestIDByteArray]struct{}, size)
}

// Has returns true if the set contains the given requestID.
func (s *SetRequestIDs) Has(e requestID) bool {
	_, ok := s.elems[requestIDToBytes(e)]
	return ok
}

// Add a requestID to the set.
func (s *SetRequestIDs) Add(e requestID) {
	s.elems[requestIDToBytes(e)] = exists
}

// Merge the set with another set.
func (s *SetRequestIDs) Merge(other *SetRequestIDs) {
	assert(s != other)
	for k := range other.elems {
		s.elems[k] = exists
	}
}

// Delete a requestID from the set.
func (s *SetRequestIDs) Delete(e requestID) {
	delete(s.elems, requestIDToBytes(e))
}

// All calls the given function for each requestID in the set.
func (s *SetRequestIDs) All(f func(requestID)) {
	for e := range s.elems {
		f(bytesToRequestID(e))
	}
}

// Slice create a copy of the set as a slice.
//
//revive:disable:unexported-return
func (s *SetRequestIDs) Slice() requestIDSlice {
	sz := s.Size()
	slice := make([]requestID, sz)
	i := 0
	for e := range s.elems {
		slice[i] = bytesToRequestID(e)
		i++
	}
	return slice
}

// Size returns the number of requestIDs in the set.
func (s *SetRequestIDs) Size() int {
	return len(s.elems)
}

// Intersection returns a new set that contains the intersection of the two sets.
func (s *SetRequestIDs) Intersection(other *SetRequestIDs) *SetRequestIDs {
	var it = NewSetRequestIDs()
	s.All(func(i requestID) {
		if other.Has(i) {
			it.Add(i)
		}
	})
	other.All(func(i requestID) {
		if s.Has(i) {
			it.Add(i)
		}
	})
	return it
}

// MapRequestIds is a map from requestIDs to values.
type MapRequestIds[V any] struct {
	elems map[requestIDByteArray]V
}

// NewMapRequestIds creates a new map from requestIDs to values.
func NewMapRequestIds[V any]() *MapRequestIds[V] {
	m := &MapRequestIds[V]{}
	m.Clear()
	return m
}

// Clear the map.
func (m *MapRequestIds[V]) Clear() {
	m.elems = make(map[requestIDByteArray]V)
}

// Has returns true if the map contains the given requestID.
func (m *MapRequestIds[V]) Has(i requestID) bool {
	_, ok := m.elems[requestIDToBytes(i)]
	return ok
}

// GetHas returns the value and true if the map contains the given requestID.
func (m *MapRequestIds[V]) GetHas(i requestID) (V, bool) {
	v, has := m.elems[requestIDToBytes(i)]
	return v, has
}

// Get returns the value for the given requestID.
func (m *MapRequestIds[V]) Get(i requestID) V {
	return m.elems[requestIDToBytes(i)]
}

// GetOrCreate returns the value for the given requestID, creating it if it doesn't exist.
func (m *MapRequestIds[V]) GetOrCreate(i requestID, f func() V) V {
	v, has := m.GetHas(i)
	if !has {
		v = f()
		m.Set(i, v)
	}
	return v
}

// MustGet returns the value for the given requestID, panicking if it doesn't exist.
func (m *MapRequestIds[V]) MustGet(i requestID) V {
	v, has := m.elems[requestIDToBytes(i)]
	assertWithMessage(has, "element missing in set")
	return v
}

// Set the value for the given requestID.
func (m *MapRequestIds[V]) Set(i requestID, v V) {
	m.elems[requestIDToBytes(i)] = v
}

// Delete the value for the given requestID.
func (m *MapRequestIds[V]) Delete(i requestID) {
	delete(m.elems, requestIDToBytes(i))
}

// Keys returns a slice of all the requestIDs in the map.
func (m *MapRequestIds[V]) Keys() requestIDSlice {
	keys := make(requestIDSlice, len(m.elems))
	i := 0
	for k := range m.elems {
		keys[i] = bytesToRequestID(k)
		i++
	}
	return keys
}

// All calls the given function for each requestID and value in the map.
func (m *MapRequestIds[V]) All(f func(requestID, V)) {
	for k, v := range m.elems {
		f(bytesToRequestID(k), v)
	}
}

// AllValues calls the given function for each value in the map.
func (m *MapRequestIds[V]) AllValues(f func(V)) {
	for _, v := range m.elems {
		f(v)
	}
}

// Find calls the given function for each requestID and value in the map and returns the first requestID and value for which the function returns true.
func (m *MapRequestIds[V]) Find(check func(requestID, V) bool) (requestID, bool) {
	for k, v := range m.elems {
		sliceID := bytesToRequestID(k)
		if check(sliceID, v) {
			return sliceID, true
		}
	}
	return nil, false
}

// Size returns the number of requestIDs in the map.
func (m *MapRequestIds[V]) Size() int {
	return len(m.elems)
}

// MapIdsIter is an iterator for a map from requestIDs to values.
type MapIdsIter[V any] struct {
	elems map[requestIDByteArray]V
	keys  []requestIDByteArray
	index int
}

// Next returns the next requestID and value in the map.
func (i *MapIdsIter[V]) Next() (requestID, V, bool) {
	if i.index == len(i.keys) {
		var zeroV V
		return nil, zeroV, false
	}
	k := i.keys[i.index]
	v := i.elems[k]
	i.index++
	return bytesToRequestID(k), v, true
}

// Iter returns an iterator for the map.
func (m *MapRequestIds[V]) Iter() *MapIdsIter[V] {
	keys := make([]requestIDByteArray, 0)
	for k := range m.elems {
		keys = append(keys, k)
	}
	return &MapIdsIter[V]{
		elems: m.elems,
		keys:  keys,
		index: 0,
	}
}

// Event IDs

type eventIDByteArray = [eventIDBytes]byte

func eventIDToBytes(id eventID) eventIDByteArray {
	var bytes eventIDByteArray
	copy(bytes[:], id)
	return bytes
}

func bytesToEventID(bytes eventIDByteArray) eventID {
	return bytes[:]
}

// SetEventIds is a set of eventIDs.
type SetEventIds struct {
	elems map[eventIDByteArray]struct{}
}

// NewSetEventIds creates a new set of eventIDs.
func NewSetEventIds(ids ...eventID) *SetEventIds {
	s := &SetEventIds{}
	s.Clear(uint(len(ids)))
	for _, id := range ids {
		s.Add(id)
	}
	return s
}

// Clear the set.
func (s *SetEventIds) Clear(size uint) {
	s.elems = make(map[eventIDByteArray]struct{}, size)
}

// Has returns true if the set contains the given eventID.
func (s *SetEventIds) Has(e eventID) bool {
	_, ok := s.elems[eventIDToBytes(e)]
	return ok
}

// Add an eventID to the set.
func (s *SetEventIds) Add(e eventID) {
	s.elems[eventIDToBytes(e)] = exists
}

// Merge the set with another set.
func (s *SetEventIds) Merge(other *SetEventIds) {
	assert(s != other)
	for k := range other.elems {
		s.elems[k] = exists
	}
}

// Delete an eventID from the set.
func (s *SetEventIds) Delete(e eventID) {
	delete(s.elems, eventIDToBytes(e))
}

// All calls the given function for each eventID in the set.
func (s *SetEventIds) All(f func(eventID)) {
	for e := range s.elems {
		f(bytesToEventID(e))
	}
}

// Slice create a copy of the set as a slice.
func (s *SetEventIds) Slice() eventIDSlice {
	sz := s.Size()
	slice := make([]eventID, sz)
	i := 0
	for e := range s.elems {
		slice[i] = bytesToEventID(e)
		i++
	}
	return slice
}

// Size returns the number of eventIDs in the set.
func (s *SetEventIds) Size() int {
	return len(s.elems)
}

// Intersection returns a new set that contains the intersection of the two sets.
func (s *SetEventIds) Intersection(other *SetEventIds) *SetEventIds {
	var it = NewSetEventIds()
	s.All(func(i eventID) {
		if other.Has(i) {
			it.Add(i)
		}
	})
	other.All(func(i eventID) {
		if s.Has(i) {
			it.Add(i)
		}
	})
	return it
}

// MapEventIds is a map from eventIDs to values.
type MapEventIds[V any] struct {
	elems map[eventIDByteArray]V
}

// NewMapEventIds creates a new map from eventIDs to values.
func NewMapEventIds[V any]() *MapEventIds[V] {
	m := &MapEventIds[V]{}
	m.Clear()
	return m
}

// Clear the map.
func (m *MapEventIds[V]) Clear() {
	m.elems = make(map[eventIDByteArray]V)
}

// Has returns true if the map contains the given eventID.
func (m *MapEventIds[V]) Has(i eventID) bool {
	_, ok := m.elems[eventIDToBytes(i)]
	return ok
}

// GetHas returns the value and true if the map contains the given eventID.
func (m *MapEventIds[V]) GetHas(i eventID) (V, bool) {
	v, has := m.elems[eventIDToBytes(i)]
	return v, has
}

// Get returns the value for the given eventID.
func (m *MapEventIds[V]) Get(i eventID) V {
	return m.elems[eventIDToBytes(i)]
}

// MustGet returns the value for the given eventID, panicking if it doesn't exist.
func (m *MapEventIds[V]) MustGet(i eventID) V {
	v, has := m.GetHas(i)
	assertWithMessage(has, "element missing in set")
	return v
}

// GetOrCreate returns the value for the given eventID, creating it if it doesn't exist.
func (m *MapEventIds[V]) GetOrCreate(i eventID, f func() V) V {
	val, has := m.GetHas(i)
	if !has {
		val = f()
		m.Set(i, val)
	}
	return val
}

// Set the value for the given eventID.
func (m *MapEventIds[V]) Set(i eventID, v V) {
	m.elems[eventIDToBytes(i)] = v
}

// Delete the value for the given eventID.
func (m *MapEventIds[V]) Delete(i eventID) {
	delete(m.elems, eventIDToBytes(i))
}

// Keys returns a slice of all the eventIDs in the map.
func (m *MapEventIds[V]) Keys() eventIDSlice {
	keys := make([]eventID, len(m.elems))
	i := 0
	m.All(func(id eventID, _ V) {
		keys[i] = id
		i++
	})
	return keys
}

// All calls the given function for each eventID and value in the map.
func (m *MapEventIds[V]) All(f func(eventID, V)) {
	m.AllWithBreak(func(ei eventID, v V) bool {
		f(ei, v)
		return false
	})
}

// AllWithBreak calls the given function for each eventID and value in the map.
// If the function retruns true, the iteration is stopped.
func (m *MapEventIds[V]) AllWithBreak(f func(eventID, V) bool) {
	for k, v := range m.elems {
		halt := f(bytesToEventID(k), v)
		if halt {
			break
		}
	}
}

// AllValues calls the given function for each value in the map.
func (m *MapEventIds[V]) AllValues(f func(V)) {
	for _, v := range m.elems {
		f(v)
	}
}

// Size returns the number of eventIDs in the map.
func (m *MapEventIds[V]) Size() int {
	return len(m.elems)
}

//revive:enable:unexported-return
