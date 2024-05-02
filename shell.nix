# SPDX-FileCopyrightText: 2024 Mass Labs
#
# SPDX-License-Identifier: GPL-3.0-or-later

{
  pkgs ? (
    let
      inherit (builtins) fetchTree fromJSON readFile;
      inherit ((fromJSON (readFile ./flake.lock)).nodes) nixpkgs gomod2nix;
    in
      import (fetchTree nixpkgs.locked) {
        overlays = [
          (import "${fetchTree gomod2nix.locked}/overlay.nix")
        ];
      }
  ),
  mkGoEnv ? pkgs.mkGoEnv,
  gomod2nix ? pkgs.gomod2nix,
  pre-commit-hooks ? pkgs.pre-commit-hooks,
  deploy-rs ? pkgs.depoly-rs,
  contracts,
  schema,
}: let
  goEnv = mkGoEnv {pwd = ./.;};

  pre-commit-check = pre-commit-hooks.lib.${pkgs.system}.run {
    src = ./.;
    hooks = {
      gotest.enable = true;
      gofmt.enable = true;
      #revive.enable = true;
      #gomod2nix.enable = true;
      goimports = {
        enable = true;
        name = "goimports";
        description = "Format my golang code";
        files = "\.go$";
        entry = let
          script = pkgs.writeShellScript "precommit-goimports" ''
            set -e
            failed=false
            for file in "$@"; do
                # redirect stderr so that violations and summaries are properly interleaved.
                if ! ${pkgs.gotools}/bin/goimports -l -d "$file" 2>&1
                then
                    failed=true
                fi
            done
            if [[ $failed == "true" ]]; then
                exit 1
            fi
          '';
        in
          builtins.toString script;
      };
    };
  };
  contracts_abi = contracts.packages.${pkgs.system}.market-build;
in
  pkgs.mkShell {
    packages =
      [
        goEnv
        gomod2nix
        deploy-rs
      ]
      ++ (with pkgs; [
        # handy
        nixpkgs-fmt
        jq
        reuse

        # dev tools
        go-outline
        gopls
        gopkgs
        go-tools
        delve
        revive
        errcheck
        unconvert

        # mass deps
        postgresql
        protobuf
        protoc-gen-go
        go-ethereum # for abigen
        gotools # for stringer
        ipfs
        contracts_abi # for run-and-deploy
      ]);

    shellHook =
      pre-commit-check.shellHook
      + ''
        env_up
        export $(egrep -v '^#' .env | xargs)
        export MASS_CONTRACTS=${contracts_abi}
        export MASS_SCHEMA=${schema}
        ./generate_code.bash

        export DBPATH=$PWD/tmp/db
        isNewPGInstance=0
        if ! test -d ./tmp/db; then
          # Initialize PostgreSQL instance
          initdb -D $DBPATH
          isNewPGInstance=1
        fi

        export PGHOST=$PWD/tmp
        # Check if PostgreSQL instance is already running
        if ! pg_isready >/dev/null 2>&1; then
          pg_ctl -D $DBPATH -l $PWD/tmp/pglogfile -o "--unix_socket_directories='$PWD/tmp'" start
        fi

        export PGDATABASE=$(echo $DATABASE_URL | cut -d'/' -f4 | cut -d'?' -f1)
        # TODO check if database exists
        if [ "$isNewPGInstance" -eq "1" ]; then
          createdb massmarket-relay-test
          psql < ./db/schema.sql
        fi

        # check if we can use the system IPFS daemon
        startedIpfs=0
        ipfs --api $IPFS_API_PATH swarm peers 1>/dev/null 2>/dev/null
        if [ "$?" -eq "1" ]; then
          mkdir -p ./tmp/ipfs
          export IPFS_PATH=$PWD/tmp/ipfs
          ipfs daemon --init > $IPFS_PATH/log.txt &
          startedIpfs=$!
          echo "started ipfs daemon. pid: $startedIpfs"
        fi

        # shutdown postgres and ipfs when we exit
        cleanup() {
            pg_ctl -D $DBPATH stop
            if [ "$startedIpfs" -gt 0 ]; then
              echo "stopping ipfs daemon..."
              kill $startedIpfs
            fi
        }
        trap cleanup EXIT
      '';
  }
