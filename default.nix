# SPDX-FileCopyrightText: 2024 Mass Labs
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
  vendorHash = "sha256-04AN/0sCgY2Vy/GIhvRWsYDmKBqCbLYrd9h7WwhjNGc=";
  ldflags = ["-X main.release=${version}"];
}
