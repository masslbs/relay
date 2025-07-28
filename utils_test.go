// SPDX-FileCopyrightText: 2024 - 2025 Mass Labs
//
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"testing"

	"github.com/masslbs/network-schema/v5/go/objects"
	"github.com/stretchr/testify/require"
)

func TestScoreRegions_CountryMatch(t *testing.T) {
	r := require.New(t)

	configured := objects.ShippingRegions{
		"A": {
			Country: "Some",
		},
		"B": {},
	}

	one := &objects.AddressDetails{Country: "Some"}
	found, err := ScoreRegions(configured, one)
	r.NoError(err)
	r.Equal(found, "A")

	two := &objects.AddressDetails{Country: "Other"}
	found, err = ScoreRegions(configured, two)
	r.NoError(err)
	r.Equal(found, "B")
}

func TestScoreRegions_NoMatch(t *testing.T) {
	r := require.New(t)

	// no blank/catch-all -> no match
	configured := objects.ShippingRegions{
		"A": {
			Country: "Some",
		},
		"B": {
			Country: "Other",
		},
	}

	one := &objects.AddressDetails{Country: "Some"}
	found, err := ScoreRegions(configured, one)
	r.NoError(err)
	r.Equal(found, "A")

	two := &objects.AddressDetails{Country: "Different One"}
	found, err = ScoreRegions(configured, two)
	r.Error(err)
	r.Empty(found)
}

func TestScoreRegions_CityMatch(t *testing.T) {
	r := require.New(t)

	configured := objects.ShippingRegions{
		"A": {
			Country:    "Same",
			PostalCode: "1234",
		},
		"B": {
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
	r.Equal(found, "B")
}

func TestScoreRegions_EdgeCase_SameCityDifferentPC(t *testing.T) {
	r := require.New(t)

	configured := objects.ShippingRegions{
		"A": {
			Country:    "Same",
			PostalCode: "1235",
			City:       "yup",
		},
		"B": {
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
	r.Equal(found, "B")
}
