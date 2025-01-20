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
  go = pkgs.go_1_22;
  enableParallelBuilding = true;
  vendorHash = "sha256-aD/+1LT7W3lviGtde1M6NT9P6ECv6/y3Ce77KfpvU8g=";
  ldflags = ["-X main.release=${version}"];
}
