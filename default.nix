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
  vendorHash = "sha256-efYssNX/9Mex+ldqS2/3/AhSjP4KXhpFmbHS4d/cnGI=";
  ldflags = ["-X main.release=${version}"];
}
