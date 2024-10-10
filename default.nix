# SPDX-FileCopyrightText: 2024 Mass Labs
#
# SPDX-License-Identifier: GPL-3.0-or-later

{
  pkgs
}:
pkgs.buildGoModule {
  pname = "relay";
  version = "0.2";
  pwd = ./.;
  src = ./.;
  go = pkgs.go_1_22;
  enableParallelBuilding = true;
  vendorHash = "sha256-5V8DdSEyO0LfajURkTouNkxKQO31736/G7qinszHV1k=";
}
