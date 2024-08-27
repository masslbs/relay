# SPDX-FileCopyrightText: 2024 Mass Labs
#
# SPDX-License-Identifier: GPL-3.0-or-later

{
  description = "Mass Market Relay";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-24.05";
    flake-utils.url = "github:numtide/flake-utils";
    pre-commit-hooks.url = "github:cachix/pre-commit-hooks.nix";

    contracts.url = "github:masslbs/contracts";
    contracts.inputs.nixpkgs.follows = "nixpkgs";
    schema = {
      url = "github:masslbs/network-schema/network-v3";
      flake = false;
    };
  };

  outputs = {
    self,
    nixpkgs,
    flake-utils,
    pre-commit-hooks,
    contracts,
    schema,
    ...
  } @ inputs: (flake-utils.lib.eachDefaultSystem
    (system: let
      pkgs = nixpkgs.legacyPackages.${system};

      # The current default sdk for macOS fails to compile go projects, so we use a newer one for now.
      # This has no effect on other platforms.
      callPackage = pkgs.darwin.apple_sdk_11_0.callPackage or pkgs.callPackage;
    in {
      packages = rec {
        relay = callPackage ./default.nix { };
        default = relay;
      };
      apps = rec {
        relay = flake-utils.lib.mkApp {drv = self.packages.${system}.relay;};
        default = relay;
      };
      devShells.default = callPackage ./shell.nix {
        inherit pre-commit-hooks;
        inherit contracts schema;
      };
    }));
}
