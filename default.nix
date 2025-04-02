# SPDX-FileCopyrightText: 2024 - 2025 Mass Labs
#
# SPDX-License-Identifier: GPL-3.0-or-later

{pkgs}: let
  version = "0.1";
in
  pkgs.buildGoModule {
    inherit version;
    pname = "relay";
    pwd = ./.;
    src = ./.;
    go = pkgs.go_1_23;
    enableParallelBuilding = true;
    vendorHash = "sha256-VI0RX0DvpZdKJ2h9GWaG/jAqdfef619CsWPeGAE4yYE=";
    ldflags = ["-X main.release=${version}"];
  }
