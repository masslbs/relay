# SPDX-FileCopyrightText: 2025 Mass Labs
#
# SPDX-License-Identifier: GPL-3.0-or-later
{
  config,
  pkgs,
  lib,
  ...
}:
with lib; let
  cfg = config.services.mm-relay;

  # Function to transform key-value pairs
  chainToEnvVar = acc: key: value: let
    newKey = "ETH_RPC_ENDPOINT_${toString key}";
    newValue = builtins.concatStringsSep ";" value;
  in
    acc // {${newKey} = newValue;};

  # Transform the original set
  envChains =
    builtins.foldl'
    (acc: key: chainToEnvVar acc key (cfg.eth.chains.${key}))
    {}
    (builtins.attrNames cfg.eth.chains);
in {
  options = {
    services.mm-relay = {
      enable = mkEnableOption (lib.mdDoc "mm-relay");

      user = mkOption {
        type = types.str;
        default = "mm-relay";
        description = mdDoc "User to run the systemd service.";
      };

      package = mkOption {
        type = types.package;
        default = pkgs.relay;
        defaultText = literalExpression "pkgs.mm-relay";
        description = lib.mdDoc "The Relay package to use.";
      };

      port = mkOption {
        type = types.port;
        default = 2222;
        description = lib.mdDoc "The port the the relay is listening on";
      };

      https-termination = mkOption {
        type = types.bool;
        default = true;
        description = "Whether to use caddy as the reverse proxy for HTTPS termination";
      };

      port-pprof = mkOption {
        type = types.port;
        default = 6666;
        defaultText = literalExpression "pkgs.mm-relay";
        description = lib.mdDoc "The profiling port";
      };

      hostname = mkOption {
        type = types.str;
        description = "the hostname to use for the HTTP TLS certificate";
      };

      prod-env = mkOption {
        type = types.bool;
        default = true;
        description = "controls whether MASS_ENV is prod or dev";
      };

      database-url = mkOption {
        type = types.str;
        default = "postgres://mm-relay@/mm-relay?host=/run/postgresql/";
        description = lib.mdDoc "The database URL";
      };

      ipfs-api-path = mkOption {
        type = types.str;
        default = "/ip4/127.0.0.1/tcp/5001";
        description = lib.mdDoc "The API endpoint for IPFS";
      };

      relay-base-url = mkOption {
        type = types.str;
        description = lib.mdDoc "The public-facing address for the relay http server";
      };

      nft-id = mkOption {
        type = types.str;
        default = "";
        description = lib.mdDoc "The NFT of the Relay. Minted from RelayReg.";
      };

      ping-interval = mkOption {
        type = types.str;
        default = "10s";
        description = lib.mdDoc "The interval at which the relay pings the database to keep the connection alive";
      };

      kick-timeout = mkOption {
        type = types.str;
        default = "30s";
        description = lib.mdDoc "The timeout after which the relay will consider the database connection dead and reconnect";
      };

      eth = {
        registries-chain-id = mkOption {
          type = types.number;
          description = lib.mdDoc "The chain id that the main registry contracts are deployed on";
        };

        chains = mkOption {
          type = types.attrsOf (types.listOf types.str);
          description = "map of chainID to rpcUrls";
        };
      };

      fixedConversion = {
        enable = mkEnableOption (lib.mdDoc "fixedConversion");

        factor = mkOption {
          type = types.number;
          description = lib.mdDoc "The factor to use for the fixed conversion";
          default = 1;
        };

        divisor = mkOption {
          type = types.number;
          description = lib.mdDoc "The divisor to use for the fixed conversion";
          default = 1;
        };
      };

      coingecko = {
        enable = mkEnableOption (lib.mdDoc "coingecko");

        api-key = mkOption {
          type = types.str;
          description = lib.mdDoc "The API key for CoinGecko";
        };
      };

      metrics = {
        enable = mkEnableOption (lib.mdDoc "metrics");

        port = mkOption {
          type = types.port;
          default = 4444;
          description = lib.mdDoc "The metrics port";
        };

        host = mkOption {
          type = types.str;
          default = "localhost";
          description = lib.mdDoc "The mertrics host";
        };
      };

      sentry = {
        enable = mkEnableOption (lib.mdDoc "sentry");

        dsn = mkOption {
          type = types.str;
          description = lib.mdDoc "The Sentry/Glitchtip DSN";
        };

        environment = mkOption {
          type = types.str;
          description = lib.mdDoc "The Sentry environment";
        };
      };
    };
  };

  config =
    mkIf cfg.enable
    {
      # IPFS (Kubo) configuration
      networking = {
        firewall.allowedTCPPorts =
          [
            4001 # ipfs swarm
          ]
          ++ optionals cfg.https-termination [80 443];
        firewall.allowedUDPPorts = [4001];
      };
      services = {
        kubo = {
          enable = true;
          settings = {
            Addresses = {
              API = [
                "/ip4/127.0.0.1/tcp/5001"
              ];
              Gateway = [
                "/ip4/127.0.0.1/tcp/8080"
              ];
            };
          };
        };
      };

      users.users.${cfg.user} = {
        isSystemUser = true;
        group = cfg.user;
        home = "/srv/relay";
        extraGroups = [config.services.kubo.group];
      };
      users.groups.mm-relay = {};

      systemd.services.mm-relay = {
        wantedBy = ["multi-user.target"];
        after = ["network.target" "postgresql.service"];
        requires = ["postgresql.service"];
        environment =
          {
            MASS_ENV =
              if cfg.prod-env == true
              then "prod"
              else "dev";
            LOG_MESSAGES = "false";
            LOG_METRICS =
              if cfg.metrics.enable
              then "false"
              else "true";
            PORT = builtins.toString cfg.port;
            PORT_PPROF = builtins.toString cfg.port-pprof;
            LISTENER_METRIC = "${cfg.metrics.host}:${builtins.toString cfg.metrics.port}";
            RELAY_BASE_URL = cfg.relay-base-url;
            RELAY_NFT_ID = cfg.nft-id;
            DATABASE_URL = cfg.database-url;
            BANG_SECRET = "g31thjPxrsJV2aXAx4zcwtiIbjxOnhBtmksnd0z2p8CWYpJxl33ltg9Ktrwte3Kf";
            ETH_STORE_REGISTRY_CHAIN_ID = builtins.toString cfg.eth.registries-chain-id;
            ETH_PRIVATE_KEY_FILE = config.age.secrets.ethereum-private.path;
            IPFS_API_PATH = cfg.ipfs-api-path;
            COINGECKO_API_KEY =
              if cfg.coingecko.enable
              then cfg.coingecko.api-key
              else "";
            TESTING_PRICE_CONVERTER_FACTOR =
              if cfg.fixedConversion.enable
              then builtins.toString cfg.fixedConversion.factor
              else "";
            TESTING_PRICE_CONVERTER_DIVISOR =
              if cfg.fixedConversion.enable
              then builtins.toString cfg.fixedConversion.divisor
              else "";
            PINATA_API_HOST = "api.pinata.cloud";
            PINATA_JWT_FILE = config.age.secrets.pinata-jwt.path;
            SENTRY_DSN = lib.optionalString (cfg.sentry.enable or false) cfg.sentry.dsn;
            SENTRY_ENVIRONMENT = lib.optionalString (cfg.sentry.enable or false) cfg.sentry.environment;
            KICK_TIMEOUT = cfg.kick-timeout;
            PING_INTERVAL = cfg.ping-interval;
          }
          // envChains;
        serviceConfig = {
          DynamicUser = true;
          Type = "exec";
          User = cfg.user;
          Restart = "on-failure";
          ExecStart = "${cfg.package}/bin/relay server";
        };
      };

      services = {
        postgresql = {
          enable = true;
          package = pkgs.postgresql_16;
          authentication = "local ${cfg.user} all trust";
          ensureUsers = [
            {
              name = cfg.user;
              ensureDBOwnership = true;
            }
          ];
          ensureDatabases = [cfg.user];
        };

        postgresqlBackup = {
          enable = true;
          databases = ["mm-relay"];
          compression = "zstd";
        };
      };
      services.caddy = lib.mkIf cfg.https-termination {
        enable = lib.mkDefault true;
        virtualHosts."${cfg.hostname}".extraConfig = ''
          reverse_proxy http://localhost:${builtins.toString cfg.port}
        '';
      };
    };
}
