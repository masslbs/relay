# SPDX-FileCopyrightText: 2024 Mass Labs
#
# SPDX-License-Identifier: MIT

.phony: all lint reuse

relay: *.go
	gomod2nix
	./generate_code.bash
	go build -o relay

lint:
	go vet ./...
	revive -formatter friendly
	reuse lint

LIC := MIT
CPY := "Mass Labs"

reuse:
	reuse annotate --license  $(LIC) --copyright $(CPY) --merge-copyrights Makefile README.md *.go go.mod *.nix .gitignore .github/workflows/test.yml .github/actions/checkout/action.yml generate_code.bash db/schema.sql gomod2nix.toml
	reuse annotate --license  $(LIC) --copyright $(CPY) --merge-copyrights --force-dot-license gen_network_typedData.json gen_contract_addresses.json .env.sample flake.lock go.sum
