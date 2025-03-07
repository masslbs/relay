# SPDX-FileCopyrightText: 2024 - 2025 Mass Labs
#
# SPDX-License-Identifier: GPL-3.0-or-later

{
  pkgs
}:
let
  version = "0.1";
in
pkgs.buildGoModule {
  inherit version;
  pname = "relay";
  pwd = ./.;
  src = ./.;
  go = pkgs.go_1_23;
  enableParallelBuilding = true;
  vendorHash = "sha256-Lcgp6/o/46Xf9I8qNOWB+s8lSIF7D4lJgV0/TJMMnVM=";
  ldflags = ["-X main.release=${version}"];
}
