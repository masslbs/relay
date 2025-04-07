# SPDX-FileCopyrightText: 2024 - 2025 Mass Labs
#
# SPDX-License-Identifier: GPL-3.0-or-later

{
  pkgs,
  contracts,
  schema,
}: let
  pre-commit-check = pre-commit-hooks.lib.${pkgs.system}.run {
    src = ./.;
    hooks = {

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
  contracts_abi = contracts.packages.${pkgs.system}.default;

  #  export DBPATH=$PWD/tmp/db
  #       isNewPGInstance=0
  #       if ! test -d ./tmp/db; then
  #         # Initialize PostgreSQL instance
  #         initdb -D $DBPATH
  #         isNewPGInstance=1
  #       fi

  #       export PGHOST=$PWD/tmp
  #       # Check if PostgreSQL instance is already running
  #       if ! pg_isready >/dev/null 2>&1; then
  #         pg_ctl -D $DBPATH -l $PWD/tmp/pglogfile -o "--unix_socket_directories='$PWD/tmp'" start
  #       fi

  #       export PGDATABASE=$(echo $DATABASE_URL | cut -d'/' -f4 | cut -d'?' -f1)
  #       # TODO check if database exists
  #       if [ "$isNewPGInstance" -eq "1" ]; then
  #         createdb massmarket-relay-test
  #         psql < ./db/schema.sql
  #       fi

  #       # check if we can use the system IPFS daemon
  #       startedIpfs=0
  #       ipfs --api $IPFS_API_PATH swarm peers 1>/dev/null 2>/dev/null
  #       if [ "$?" -eq "1" ]; then
  #         mkdir -p ./tmp/ipfs
  #         export IPFS_PATH=$PWD/tmp/ipfs
  #         ipfs daemon --init > $IPFS_PATH/log.txt &
  #         startedIpfs=$!
  #         echo "started ipfs daemon. pid: $startedIpfs"
  #       fi

  #       # shutdown postgres and ipfs when we exit
  #       cleanup() {
  #           pg_ctl -D $DBPATH stop
  #           if [ "$startedIpfs" -gt 0 ]; then
  #             echo "stopping ipfs daemon..."
  #             kill $startedIpfs
  #           fi
  #       }
  #       trap cleanup EXIT