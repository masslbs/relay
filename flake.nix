# SPDX-FileCopyrightText: 2024 - 2025 Mass Labs
#
# SPDX-License-Identifier: GPL-3.0-or-later

{
  description = "Mass Market Relay";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-24.11";
    systems.url = "github:nix-systems/default";
    flake-parts = {
      url = "github:hercules-ci/flake-parts";
    };
    flake-root.url = "github:srid/flake-root";

    process-compose-flake = {
      url = "github:Platonic-Systems/process-compose-flake";
    };
    services-flake.url = "github:juspay/services-flake";

    pre-commit-hooks = {
      url = "github:cachix/git-hooks.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    contracts.url = "github:masslbs/contracts";
    foundry.follows = "contracts/foundry";

    schema.url = "github:masslbs/network-schema/v4.0";
  };

  outputs = inputs @ {
    flake-parts,
    systems,
    foundry,
    contracts,
    schema,
    ...
  }:
    flake-parts.lib.mkFlake {inherit inputs;} {
      systems = import systems;
      imports = [
        inputs.flake-root.flakeModule
        inputs.pre-commit-hooks.flakeModule
        inputs.process-compose-flake.flakeModule
      ];

      flake = {
        processComposeModules.default = ./services.nix;
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
          # all but the relay
          local-testnet-dev = {
            inherit services imports cli;
          };
          local-testnet = {
            inherit imports cli;
            services =
              services
              // {
                relay.enable = true;
              };
          };
        };

        pre-commit = {
          check.enable = true;
          settings = {
            src = ./.;
            hooks = {
              typos.enable = true;
              gotest.enable = true;
              gofmt.enable = true;
            };
          };
        };

        devShells.default = pkgs.mkShell {
          # local devshell scripts need to come first.
          buildInputs =
            [
              self'.packages.local-testnet-dev
              pkgs.typos-lsp # code spell checker
              pkgs.nixd
            ]
            ++ config.pre-commit.settings.enabledPackages
            ++ (with pkgs; [
              # handy
              nixpkgs-fmt
              jq
              reuse
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

        packages = rec {
          relay = pkgs.callPackage ./default.nix {};
          default = relay;
        };
      };
    };
}
