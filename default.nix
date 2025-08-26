# SPDX-FileCopyrightText: 2024 - 2025 Mass Labs
#
# SPDX-License-Identifier: GPL-3.0-or-later
{pkgs}: let
  version = "5";
in
  pkgs.buildGoModule {
    inherit version;
    pname = "relay";
    pwd = ./.;
    src = ./.;
    enableParallelBuilding = true;
    vendorHash = "sha256-2ox4aoizzteaKeW+UrU01jtGXWfHe9FcM2vOmIwjbGU=";
    ldflags = ["-X main.release=${version}"];
    doCheck = true;
  }
