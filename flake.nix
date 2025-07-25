# SPDX-FileCopyrightText: 2024 - 2025 Mass Labs
#
# SPDX-License-Identifier: GPL-3.0-or-later
{
  description = "Mass Market Relay";

  inputs = {
    # to get local-testnet the right addresses we use contracts' nixpkgs
    # nixpkgs.url = "github:nixos/nixpkgs/nixos-25.05";
    systems.url = "github:nix-systems/default";
    flake-parts.url = "github:hercules-ci/flake-parts";

    process-compose-flake.url = "github:Platonic-Systems/process-compose-flake";
    services-flake.url = "github:juspay/services-flake";

    pre-commit-hooks = {
      url = "github:cachix/git-hooks.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    contracts.url = "github:masslbs/contracts/stage1";
    # see above
    nixpkgs.follows = "contracts/nixpkgs";
    foundry.follows = "contracts/foundry";

    schema.url = "github:masslbs/network-schema";
    # to align pythonPackages between the two
    schema.inputs.nixpkgs.follows = "pystoretest/nixpkgs";

    pystoretest.url = "github:masslbs/pystoretest";
    pystoretest.inputs.contracts.follows = "contracts";
    pystoretest.inputs.network-schema.follows = "schema";
  };

  outputs = inputs @ {
    systems,
    contracts,
    schema,
    pystoretest,
    foundry,
    ...
  }:
    inputs.flake-parts.lib.mkFlake {inherit inputs;} {
      systems = import systems;
      imports = [
        inputs.pre-commit-hooks.flakeModule
        inputs.process-compose-flake.flakeModule
      ];

      flake = {
        processComposeModules.default = ./services.nix;
        nixosModules.default = ./nixosModule.nix;
      };
      perSystem = {
        pkgs,
        system,
        config,
        self',
        lib,
        ...
      }: let
        contracts_abi = contracts.packages.${pkgs.system}.default;

        relay = pkgs.callPackage ./default.nix {};
      in {
        _module.args.pkgs = import inputs.nixpkgs {
          inherit system;
          overlays = [
            foundry.overlay
          ];
        };
        process-compose = let
          cli = {
            options = {
              no-server = false;
              port = 8321;
            };
          };
          imports = [
            inputs.services-flake.processComposeModules.default
            inputs.contracts.processComposeModules.default
            inputs.self.processComposeModules.default
          ];
          services = {
            relay.enable = true;
            ipfs.enable = true;
            postgres."psql-relay-test" = {
              enable = true;
              initialDatabases = [
                {
                  name = "mm-relay-test";
                  schemas = [./db/schema.sql];
                }
              ];
            };
            anvil.enable = true;
            deploy-contracts.enable = true;
          };
        in {
          local-testnet = {
            inherit imports cli;
            services =
              services
              // {
                relay_generate_shop = {
                  enable = true;
                  command = "${pystoretest.packages.${pkgs.system}.pystoretest}/bin/pystoretest -k make_hydration_data -v";
                };
              };
          };
        };

        pre-commit = {
          check.enable = true;
          settings = {
            src = ./.;
            hooks = {
              typos.enable = true;
              gofmt.enable = true;
              alejandra.enable = true;
              gotest.enable = true;
            };
          };
        };

        devShells.default = pkgs.mkShell {
          buildInputs =
            [
              self'.packages.local-testnet
              pystoretest.packages.${pkgs.system}.pystoretest
            ]
            ++ config.pre-commit.settings.enabledPackages
            ++ (with pkgs; [
              # handy
              alejandra
              jq
              reuse
              nixd
              typos-lsp

              # dev tools
              go_1_23
              go-outline
              gopls
              gopkgs
              go-tools
              delve
              revive
              errcheck
              unconvert
              godef
              clang

              # mass deps
              postgresql # TODO: sync with services version
              protobuf
              protoc-gen-go
              go-ethereum # for abigen
              gotools # for stringer
              ipfs
              contracts_abi # abi code generation
            ]);

          shellHook = ''
            ${config.pre-commit.settings.installationScript}
            export $(egrep -v '^#' .env | xargs)
            export MASS_CONTRACTS=${contracts_abi}
            export MASS_SCHEMA=${schema}
            export IPFS_PATH=$PWD/data/ipfs
          '';
        };

        packages.default = relay;
        # TODO: this approach to run the pystoretest suite might be flawed because of the sandboxing of nix
        # packages.default = relay.overrideAttrs (oldAttrs: {
        #   doCheck = true;
        #   checkPhase = ''
        #     # Run original check phase first
        #     ${oldAttrs.checkPhase or ""}

        #     echo "Running custom check phase with local-testnet and pystoretest..."

        #     # Start local-testnet
        #     tempDir=$(mktemp -d)
        #     pushd $tempDir
        #     mkdir -p data/ipfs
        #     echo "IPFS_PATH=$tempDir/data/ipfs" >> .env
        #     # TODO: -D once deploy-contracts is fixed
        #     ${self'.packages.local-testnet}/bin/local-testnet --read-only -t=false up
        #     popd

        #     # Wait for services to be ready
        #     sleep 10

        #     # Run pystoretest against the local testnet
        #     export RELAY_HTTP_ADDRESS=http://localhost:4444
        #     export RELAY_PING=0.1
        #     export ETH_PRIVATE_KEY=ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
        #     export ETH_RPC_URL=http://localhost:8545
        #     ${pystoretest.packages.${pkgs.system}.default}/bin/pystoretest --benchmark-skip -n auto

        #     # Clean up
        #     ${self'.packages.local-testnet}/bin/local-testnet --read-only down
        #   '';
        # });
      };
    };
}
