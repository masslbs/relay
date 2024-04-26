# SPDX-FileCopyrightText: 2024 Mass Labs
#
# SPDX-License-Identifier: GPL-3.0-or-later

.phony: all lint reuse

relay: *.go
	./generate_code.bash
	go build -o relay

lint:
	go vet ./...
	revive -formatter friendly
	reuse lint

LIC := GPL-3.0-or-later
CPY := "Mass Labs"

reuse:
	reuse annotate --license  $(LIC) --copyright $(CPY) --merge-copyrights Makefile README.md *.go go.mod *.nix .gitignore .github/workflows/test.yml .github/actions/checkout/action.yml generate_code.bash db/schema.sql
	reuse annotate --license  $(LIC) --copyright $(CPY) --merge-copyrights --force-dot-license gen_network_typedData.json gen_contract_addresses.json .env.sample flake.lock go.sum
