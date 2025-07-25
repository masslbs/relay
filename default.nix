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
    vendorHash = "sha256-Zw1KCxXYeeoVaqN+/Y6ckJmY1gwaracLDjLKagIyg+o=";
    ldflags = ["-X main.release=${version}"];
    # # TODO: we build the package twice (once again in serviecs, i think)
    # # Let's not run the tests twice, too at least. The linking time is excruciatingly long.
    # doCheck = false;
  }
