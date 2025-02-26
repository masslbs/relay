// SPDX-FileCopyrightText: 2024 - 2025 Mass Labs
//
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"testing"

	"github.com/masslbs/network-schema/go/objects"
	"github.com/stretchr/testify/require"
)

func TestScoreRegions_CountryMatch(t *testing.T) {
	r := require.New(t)

	configured := map[string]*objects.AddressDetails{
		"A": {
			Name:    "A",
			Country: "Some",
		},
		"B": {
			Name: "B",
		},
	}

	one := &objects.AddressDetails{Country: "Some"}
	found, err := ScoreRegions(configured, one)
	r.NoError(err)
	r.Equal(found.Name, "A")

	two := &objects.AddressDetails{Country: "Other"}
	found, err = ScoreRegions(configured, two)
	r.NoError(err)
	r.Equal(found.Name, "B")
}

func TestScoreRegions_NoMatch(t *testing.T) {
	r := require.New(t)

	// no blank/catch-all -> no match
	configured := map[string]*objects.AddressDetails{
		"A": {
			Name:    "A",
			Country: "Some",
		},
		"B": {
			Name:    "B",
			Country: "Other",
		},
	}

	one := &objects.AddressDetails{Country: "Some"}
	found, err := ScoreRegions(configured, one)
	r.NoError(err)
	r.Equal(found.Name, "A")

	two := &objects.AddressDetails{Country: "Different One"}
	found, err = ScoreRegions(configured, two)
	r.Error(err)
	r.Nil(found)
}

func TestScoreRegions_CityMatch(t *testing.T) {
	r := require.New(t)

	configured := map[string]*objects.AddressDetails{
		"A": {
			Name:       "A",
			Country:    "Same",
			PostalCode: "1234",
		},
		"B": {
			Name:       "B",
			Country:    "Same",
			PostalCode: "1234",
			City:       "yup",
		},
	}

	one := &objects.AddressDetails{
		Country:    "Same",
		PostalCode: "1234",
		City:       "yup",
	}
	found, err := ScoreRegions(configured, one)
	r.NoError(err)
	r.Equal(found.Name, "B")
}

func TestScoreRegions_EdgeCase_SameCityDifferentPC(t *testing.T) {
	r := require.New(t)

	configured := map[string]*objects.AddressDetails{
		"A": {
			Name:       "A",
			Country:    "Same",
			PostalCode: "1235",
			City:       "yup",
		},
		"B": {
			Name:       "B",
			Country:    "Same",
			PostalCode: "1234",
			City:       "yup",
		},
	}

	one := &objects.AddressDetails{
		Country:    "Same",
		PostalCode: "1234",
		City:       "yup",
	}
	found, err := ScoreRegions(configured, one)
	r.NoError(err)
	r.Equal(found.Name, "B")
}
