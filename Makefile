# SPDX-FileCopyrightText: 2024 - 2025 Mass Labs
#
# SPDX-License-Identifier: GPL-3.0-or-later

.phony: all lint reuse

relay: *.go
	./update_version.bash
	./generate_code.bash
	go build -o relay

lint:
	go vet ./...
	revive -formatter friendly
	reuse lint

LIC := GPL-3.0-or-later
CPY := "Mass Labs"

reuse:
	reuse annotate --license  $(LIC) --copyright $(CPY) --merge-copyrights Makefile README.md *.go internal/contractabis/*.go go.mod *.nix .gitignore .github/workflows/test.yml .github/actions/checkout/action.yml *.bash db/schema.sql
	reuse annotate --license  $(LIC) --copyright $(CPY) --merge-copyrights --force-dot-license internal/contractabis/gen_contract_addresses.json .env.sample flake.lock go.sum
