#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2024 Mass Labs
#
# SPDX-License-Identifier: GPL-3.0-or-later

set -euo pipefail

# Get version and commit
SCHEMA_VERSION=`cat $MASS_SCHEMA/VERSION`
SCHEMA_COMMIT_HASH=$(jq -r '.nodes["schema"].locked.rev' flake.lock)
CONTRACTS_COMMIT_HASH=$(jq -r '.nodes["contracts"].locked.rev' flake.lock)

# protobuf file and encoding helpers from network schema
cp $MASS_SCHEMA/schema.proto network-schema.proto
chmod u+w network-schema.proto
protoc --go_out=paths=source_relative:. --go_opt="Mnetwork-schema.proto=github.com/masslbs/network-schema;main" network-schema.proto
# Prepend comment with versioning info
sed -i "1i // Generated from $MASS_SCHEMA/schema.proto at version v$SCHEMA_VERSION ($SCHEMA_COMMIT_HASH)\n" network-schema.pb.go
mv network-schema.pb.go gen_network_schema.pb.go
rm network-schema.proto

cp $MASS_SCHEMA/typedData.json gen_network_typedData.json
go run generate_typedData_event_helper.go $SCHEMA_VERSION $SCHEMA_COMMIT_HASH > gen_typedData_event_helper.go

go run generate_types.go $SCHEMA_VERSION $SCHEMA_COMMIT_HASH > gen_types.go
go run generate_constants.go $SCHEMA_VERSION $SCHEMA_COMMIT_HASH > gen_constants.go

# smart contract wrapper
abigen --pkg main --type ERC20 --out gen_erc20.go --abi $MASS_CONTRACTS/abi/ERC20.json
abigen --pkg main --type RegRelay --out gen_registry_relay.go --abi $MASS_CONTRACTS/abi/RelayReg.json
abigen --pkg main --type RegStore --out gen_registry_store.go --abi  $MASS_CONTRACTS/abi/StoreReg.json
#abigen --pkg main --type Payments --out gen_payments.go --abi $MASS_CONTRACTS/abi/Payments.json
abigen --pkg main --type PaymentsByAddress --out gen_payments_by_address.go --abi $MASS_CONTRACTS/abi/PaymentsByAddress.json
sed -i "1i // Generated from abi/ERC20.json - git at $CONTRACTS_COMMIT_HASH\n" gen_erc20.go
sed -i "1i // Generated from abi/RelayReg.json - git at $CONTRACTS_COMMIT_HASH\n" gen_registry_relay.go
sed -i "1i // Generated from abi/StoreReg.json - git at $CONTRACTS_COMMIT_HASH\n" gen_registry_store.go
#sed -i "1i // Generated from abi/Payments.json - git at $CONTRACTS_COMMIT_HASH\n" gen_payments.go
sed -i "1i // Generated from abi/PaymentsByAddress.json - git at $CONTRACTS_COMMIT_HASH\n" gen_payments_by_address.go

cp $MASS_CONTRACTS/deploymentAddresses.json gen_contract_addresses.json

go generate
go fmt ./...

make reuse

go vet
