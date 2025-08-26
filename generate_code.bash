#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2024 - 2025 Mass Labs
#
# SPDX-License-Identifier: GPL-3.0-or-later

set -euo pipefail

# Get version and commit
SCHEMA_VERSION=`cat $MASS_SCHEMA/VERSION`
SCHEMA_COMMIT_HASH=$(jq -r '.nodes["schema"].locked.rev' flake.lock)
CONTRACTS_COMMIT_HASH=$(jq -r '.nodes["contracts"].locked.rev' flake.lock)

# TODO: split up sql constants into a separate file and use other constants from imported schema module
go run generate_constants.go $SCHEMA_VERSION $SCHEMA_COMMIT_HASH > gen_constants.go

# smart contract wrapper
pushd internal/contractabis
abigen --pkg contractsabi --type ERC20 --out gen_erc20.go --abi $MASS_CONTRACTS/abi/ERC20.json
abigen --pkg contractsabi --type RegRelay --out gen_registry_relay.go --abi $MASS_CONTRACTS/abi/RelayReg.json
abigen --pkg contractsabi --type RegShop --out gen_registry_shop.go --abi  $MASS_CONTRACTS/abi/ShopReg.json
abigen --pkg contractsabi --type OrderPayment --out gen_order_payment.go --abi $MASS_CONTRACTS/abi/OrderPayment.json
abigen --pkg contractsabi --type OrderPaymentsFactory --out gen_order_payments_factory.go --abi $MASS_CONTRACTS/abi/OrderPaymentsFactory.json
sed -i "1i // Generated from abi/ERC20.json - git at $CONTRACTS_COMMIT_HASH\n" gen_erc20.go
sed -i "1i // Generated from abi/RelayReg.json - git at $CONTRACTS_COMMIT_HASH\n" gen_registry_relay.go
sed -i "1i // Generated from abi/ShopReg.json - git at $CONTRACTS_COMMIT_HASH\n" gen_registry_shop.go
sed -i "1i // Generated from abi/OrderPayment.json - git at $CONTRACTS_COMMIT_HASH\n" gen_order_payment.go
sed -i "1i // Generated from abi/OrderPaymentsFactory.json - git at $CONTRACTS_COMMIT_HASH\n" gen_order_payments_factory.go

cp $MASS_CONTRACTS/deploymentAddresses.json gen_contract_addresses.json
popd

go generate
go fmt ./...

make reuse

go vet
