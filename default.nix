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
    vendorHash = "sha256-utrLuTj93AD56zTVN9R2wRy1siTNL8NeMFFR6j04e5A=";
    ldflags = ["-X main.release=${version}"];
    # TODO: we build the package twice (once again in serviecs, i think)
    # Let's not run the tests twice, too at least. The linking time is excruciatingly long.
    doCheck = false;
  }
