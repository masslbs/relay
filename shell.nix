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
