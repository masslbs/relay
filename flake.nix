# SPDX-FileCopyrightText: 2024 - 2025 Mass Labs
#
# SPDX-License-Identifier: GPL-3.0-or-later
{
  description = "Mass Market Relay";

  inputs = {
    systems.url = "github:nix-systems/default";
    flake-parts.url = "github:hercules-ci/flake-parts";

    process-compose-flake.url = "github:Platonic-Systems/process-compose-flake";
    services-flake.url = "github:juspay/services-flake";

    pre-commit-hooks = {
      url = "github:cachix/git-hooks.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    contracts.url = "github:masslbs/contracts";
    # to reduce derivation size we use this nixpkgs for everything below

    schema.url = "github:masslbs/network-schema/v5-dev";
    nixpkgs.follows = "schema/nixpkgs";

    pystoretest.url = "github:masslbs/pystoretest/network-v5";
    pystoretest.inputs = {
      nixpkgs.follows = "nixpkgs";
      contracts.follows = "contracts";
      network-schema.follows = "schema";
    };
  };

  outputs = inputs @ {
    systems,
    contracts,
    schema,
    pystoretest,
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

        checks.pystoretest = pkgs.nixosTest {
          name = "pystoretest-integration";

          nodes.machine = {
            virtualisation = {
              cores = 6;
              memorySize = 4096;
              diskSize = 4096;
            };

            users.users.testnet = {
              isNormalUser = true;
              description = "User for running local-testnet";
              group = "testnet";
            };

            users.users.tester = {
              isNormalUser = true;
              description = "User for running pystoretest";
              group = "tester";
            };

            users.groups.testnet = {};
            users.groups.tester = {};

            environment.systemPackages = [
              self'.packages.local-testnet
              pystoretest.packages.${pkgs.system}.pystoretest
              pkgs.curl
              pkgs.jq
              pkgs.sudo
            ];
          };

          testScript = ''
            machine.start()
            machine.wait_for_unit("multi-user.target")

            # Set up environment for testnet user
            machine.execute("sudo -u testnet mkdir -p /home/testnet/test-env/data/ipfs")
            machine.execute("sudo -u testnet sh -c 'cd /home/testnet/test-env && echo \"IPFS_PATH=/home/testnet/test-env/data/ipfs\" >> .env'")
            machine.execute("chown -R testnet:testnet /home/testnet/test-env")

            # Start local-testnet in daemon mode as testnet user
            machine.execute("sudo -u testnet sh -c 'cd /home/testnet/test-env && local-testnet -D -L logs/process-compose.log'")

            # Wait for services to be ready (following CI pattern)
            machine.execute("""
              timeout=10
              while [ $timeout -gt 0 ]; do
                if curl --retry 5 --retry-all-errors http://localhost:8321/live 2>/dev/null; then
                  break
                fi
                echo "Waiting for process-compose to be ready..."
                timeout=$((timeout - 1))
                sleep 5
              done
            """, timeout=120)

            # Check if relay is ready
            machine.execute("""
              timeout=10
              while [ $timeout -gt 0 ]; do
                isReady=$(curl -s http://localhost:8321/processes | jq -r '.data[] | select(.name == "relay") | .is_ready' 2>/dev/null || echo "")
                if [ "$isReady" == "Ready" ]; then
                  break
                fi
                echo "Relay is not ready, waiting for $timeout seconds"
                timeout=$((timeout - 1))
                sleep 5
              done

              if [ "$isReady" != "Ready" ]; then
                echo "Relay is not ready"
                exit 1
              fi
            """, timeout=120)

            # Verify services are accessible
            machine.execute("curl http://localhost:4444/health")
            machine.execute("curl http://localhost:5001/api/v0/version -X POST")
            machine.execute("curl http://localhost:8545/ -X POST -H 'content-type: application/json' --data-raw '{\"jsonrpc\":\"2.0\",\"method\":\"eth_blockNumber\",\"params\":[],\"id\":0}'")

            # Set up test environment for tester user
            machine.execute("sudo -u tester mkdir -p /home/tester/test-run")
            machine.execute("chown -R tester:tester /home/tester/test-run")

            # Run pystoretest against the local testnet as tester user
            machine.execute("""
              sudo -u tester sh -c 'cd /home/tester/test-run && \
              export RELAY_HTTP_ADDRESS=http://localhost:4444 && \
              export RELAY_PING=0.1 && \
              export ETH_PRIVATE_KEY=ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 && \
              export ETH_RPC_URL=http://localhost:8545 && \
              pystoretest --benchmark-skip -n auto'
            """, timeout=300)

            # Clean up
            machine.execute("sudo -u testnet sh -c 'cd /home/testnet/test-env && ${self'.packages.local-testnet}/bin/local-testnet down'")
          '';
        };
      };
    };
}
