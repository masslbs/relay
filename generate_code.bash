#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2024 - 2025 Mass Labs
#
# SPDX-License-Identifier: GPL-3.0-or-later

set -euo pipefail

# Get version and commit
SCHEMA_VERSION=`cat $MASS_SCHEMA/VERSION`
SCHEMA_COMMIT_HASH=$(jq -r '.nodes["schema"].locked.rev' flake.lock)
CONTRACTS_COMMIT_HASH=$(jq -r '.nodes["contracts"].locked.rev' flake.lock)

# protobuf file and encoding helpers from network schema
mkdir network-schema/
cp $MASS_SCHEMA/*.proto network-schema/
chmod u+w network-schema/*.proto
for input in network-schema/*.proto; do
  goFname="$(basename $input | sed 's/.proto/.pb.go/')"
  echo "Generating $goFname from $input"
  protoc \
    -I=network-schema \
    --go_out=paths=source_relative:. \
    --go_opt="Msubscription.proto=github.com/masslbs/network-schema;main" \
    --go_opt="Mtransport.proto=github.com/masslbs/network-schema;main" \
    --go_opt="Mshop_requests.proto=github.com/masslbs/network-schema;main" \
    --go_opt="Mauthentication.proto=github.com/masslbs/network-schema;main" \
    --go_opt="Mbase_types.proto=github.com/masslbs/network-schema;main" \
    --go_opt="Merror.proto=github.com/masslbs/network-schema;main" \
    --go_opt="M$(basename $input)=github.com/masslbs/network-schema;main" \
    $input
  # Prepend comment with versioning info
  sed -i "1i // Generated from $MASS_SCHEMA/$input at version v$SCHEMA_VERSION ($SCHEMA_COMMIT_HASH)\n" $goFname
  mv $goFname gen_network_$goFname
done
rm -r network-schema/

sed -i 's/ErrorCodes_ERROR_CODES_/ErrorCodes_/' gen_network_error.pb.go

go run generate_constants.go $SCHEMA_VERSION $SCHEMA_COMMIT_HASH > gen_constants.go

# smart contract wrapper
pushd internal/contractabis
abigen --pkg contractsabi --type ERC20 --out gen_erc20.go --abi $MASS_CONTRACTS/abi/ERC20.json
abigen --pkg contractsabi --type RegRelay --out gen_registry_relay.go --abi $MASS_CONTRACTS/abi/RelayReg.json
abigen --pkg contractsabi --type RegShop --out gen_registry_shop.go --abi  $MASS_CONTRACTS/abi/ShopReg.json
abigen --pkg contractsabi --type PaymentsByAddress --out gen_payments_by_address.go --abi $MASS_CONTRACTS/abi/PaymentsByAddress.json
sed -i "1i // Generated from abi/ERC20.json - git at $CONTRACTS_COMMIT_HASH\n" gen_erc20.go
sed -i "1i // Generated from abi/RelayReg.json - git at $CONTRACTS_COMMIT_HASH\n" gen_registry_relay.go
sed -i "1i // Generated from abi/ShopReg.json - git at $CONTRACTS_COMMIT_HASH\n" gen_registry_shop.go
#sed -i "1i // Generated from abi/Payments.json - git at $CONTRACTS_COMMIT_HASH\n" gen_payments.go
sed -i "1i // Generated from abi/PaymentsByAddress.json - git at $CONTRACTS_COMMIT_HASH\n" gen_payments_by_address.go

cp $MASS_CONTRACTS/deploymentAddresses.json gen_contract_addresses.json
popd

go generate
go fmt ./...

make reuse

go vet
