# SPDX-FileCopyrightText: 2025 Mass Labs
#
# SPDX-License-Identifier: GPL-3.0-or-later
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.services;
  relay = pkgs.callPackage ./default.nix {};
in {
  options = {
    services.ipfs = {
      enable = lib.mkEnableOption "Start ipfs";
    };
    services.relay = {
      enable = lib.mkEnableOption "Start relay";
    };
  };
  config = {
    settings.processes = {
      # TODO: conditional on present in system..?
      ipfs = {
        command = "${pkgs.ipfs}/bin/ipfs daemon --init --offline";
        ready_log_line = "Daemon is ready";
      };
      relay = {
        command = "${relay}/bin/relay server";
        log_location = "logs/relay.log";
        readiness_probe = {
          http_get = {
            host = "localhost";
            port = 4444;
            scheme = "http";
            path = "/health";
          };
        };
        environment = {
          MASS_ENV = "dev";
          LOG_MESSAGES = "false";
          LOG_METRICS = "false";
          LISTENER_METRIC = "localhost:5555";
          PORT = "4444";
          PORT_PPROF = "6666";
          DATABASE_URL = "postgres://localhost:5432/mm-relay-test";
          BANG_SECRET = "vYmqyThWIqbqjF3EStp3BdkRIeubjnnP";
          ETH_STORE_REGISTRY_CHAIN_ID = "31337";
          ETH_RPC_ENDPOINT_31337 = "ws://localhost:8545";
          ETH_PRIVATE_KEY = "2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6";
          IPFS_API_PATH = "/ip4/127.0.0.1/tcp/5001";
          RELAY_BASE_URL = "http://localhost:4444";
          PINATA_API_HOST = "api.pinata.cloud";
          PING_INTERVAL = "2s";
          KICK_TIMEOUT = "7s";
        };
        depends_on = {
          "anvil".condition = "process_log_ready";
          "psql-relay-test".condition = "process_healthy";
          "ipfs".condition = "process_log_ready";
        };
      };
    };
  };
}
