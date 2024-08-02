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
  vendorHash = "sha256-fuej9Vmr/eOMKH2vURqa0b38I2+XfvwI10kYf5sJn/k=";
}
