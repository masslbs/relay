# SPDX-FileCopyrightText: 2024 - 2025 Mass Labs
#
# SPDX-License-Identifier: GPL-3.0-or-later

{pkgs}: let
  version = "4";
in
  pkgs.buildGoModule {
    inherit version;
    pname = "relay";
    pwd = ./.;
    src = ./.;
    go = pkgs.go_1_23;
    enableParallelBuilding = true;
    vendorHash = "sha256-vOOWG0/VEvG9Cy1zOecxboC+HZrlWzgoG1KuWyNIZMc=";
    ldflags = ["-X main.release=${version}"];
  }
