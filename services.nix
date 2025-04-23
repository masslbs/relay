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

  check_ipfs_first = pkgs.writeShellScriptBin "check_ipfs_first" ''
    # Check if IPFS is already running by querying the API
    if curl -s -X POST "http://localhost:5001/api/v0/id" > /dev/null 2>&1; then
      echo "Daemon is ready # IPFS is already running"
      # Keep the process alive but do nothing
      while true; do
        sleep 60
      done
    else
      echo "Starting IPFS daemon..."
      exec ${pkgs.ipfs}/bin/ipfs daemon --init --offline
    fi
  '';
in {
  options = {
    services.ipfs = {enable = lib.mkEnableOption "Start ipfs";};
    services.relay = {enable = lib.mkEnableOption "Start relay";};
    services.relay_generate_shop = {
      enable = lib.mkEnableOption "Start generate_shop";
      command = lib.mkOption {
        type = lib.types.str;
        default = "/bin/false";
        description = "Command to run for generate_shop service";
      };
    };
  };
  config = {
    settings.processes = {
      ipfs = {
        command = check_ipfs_first;
        ready_log_line = "Daemon is ready";
        liveness_probe.http_get = {
          host = "localhost";
          port = 5001;
          scheme = "http";
          path = "/version";
        };
      };
      relay = {
        command = "${relay}/bin/relay server";
        log_location = "logs/relay.log";
        ready_log_line = "relay.run";
        liveness_probe.http_get = {
          host = "localhost";
          port = 4444;
          scheme = "http";
          path = "/health";
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
          TESTING_PRICE_CONVERTER_FACTOR = "1500";
          TESTING_PRICE_CONVERTER_DIVISOR = "1";
        };
        depends_on = {
          "anvil".condition = "process_log_ready";
          "deploy-contracts".condition = "process_completed";
          "psql-relay-test".condition = "process_healthy";
          "ipfs".condition = "process_log_ready";
        };
      };
      relay_generate_shop = {
        command = cfg.relay_generate_shop.command;
        environment = {
          TEST_MAKE_HYDRATION_DATA = "/tmp/shopgen-metadata";
          RELAY_PING = "0.2";
          RELAY_HTTP_ADDRESS = "http://localhost:4444";
          ETH_PRIVATE_KEY = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"; # anvil key 0
          JS_SAFE = "1";
        };
        depends_on = {
          "relay".condition = "process_log_ready";
        };
      };
    };
  };
}
