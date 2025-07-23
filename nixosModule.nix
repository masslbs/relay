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
      enable = mkEnableOption (mdDoc "mm-relay");

      user = mkOption {
        type = types.str;
        default = "mm-relay";
        description = mdDoc "User to run the systemd service.";
      };

      package = mkOption {
        type = types.package;
        default = pkgs.relay;
        defaultText = literalExpression "pkgs.mm-relay";
        description = mdDoc "The Relay package to use.";
      };

      port = mkOption {
        type = types.port;
        default = 2222;
        description = mdDoc "The port the the relay is listening on";
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
        description = mdDoc "The profiling port";
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
        description = mdDoc "The database URL";
      };

      ipfs-api-path = mkOption {
        type = types.str;
        default = "/ip4/127.0.0.1/tcp/5001";
        description = mdDoc "The API endpoint for IPFS";
      };

      # issue#55: remove me
      pinata = {
        enable = mkOption {
          type = types.bool;
          default = cfg.prod-env;
        };
        hostname = mkOption {
          type = types.str;
          default = "api.pinata.cloud";
        };
        key-file = mkOption {
          type = types.nullOr types.path;
          default =
            if (config.age or null) != null && (config.age.secrets or null) != null && (config.age.secrets.pinata-jwt or null) != null
            then config.age.secrets.pinata-jwt.path
            else null;
        };
      };

      relay-base-url = mkOption {
        type = types.str;
        description = mdDoc "The public-facing address for the relay http server";
      };

      nft-id = mkOption {
        type = types.str;
        default = "";
        description = mdDoc "The NFT of the Relay. Minted from RelayReg.";
      };

      ping-interval = mkOption {
        type = types.str;
        default = "10s";
        description = mdDoc "The interval at which the relay pings the database to keep the connection alive";
      };

      kick-timeout = mkOption {
        type = types.str;
        default = "30s";
        description = mdDoc "The timeout after which the relay will consider the database connection dead and reconnect";
      };

      eth = {
        private-key-file = mkOption {
          type = types.nullOr types.path;
          default =
            if (config.age or null) != null && (config.age.secrets or null) != null && (config.age.secrets.ethereum-private-key or null) != null
            then config.age.secrets.ethereum-private-key.path
            else null;
          defaultText = literalExpression "config.age.secrets.ethereum-private-key.path";
          description = mdDoc "The private key file the relay should read to get the key data for its blockchain writes";
        };

        private-key = mkOption {
          type = types.nullOr types.str;
          default = null;
          description = mdDoc "The private key data the relay should use for its blockchain writes (overrides key-file if set)";
        };

        registries-chain-id = mkOption {
          type = types.number;
          description = mdDoc "The chain id that the main registry contracts are deployed on";
        };

        chains = mkOption {
          type = types.attrsOf (types.listOf types.str);
          description = "map of chainID to rpcUrls";
        };
      };

      fixedConversion = {
        enable = mkEnableOption (mdDoc "fixedConversion");

        factor = mkOption {
          type = types.number;
          description = mdDoc "The factor to use for the fixed conversion";
          default = 1;
        };

        divisor = mkOption {
          type = types.number;
          description = mdDoc "The divisor to use for the fixed conversion";
          default = 1;
        };
      };

      coingecko = {
        enable = mkEnableOption (mdDoc "coingecko");

        api-key = mkOption {
          type = types.str;
          description = mdDoc "The API key for CoinGecko";
        };
      };

      metrics = {
        enable = mkEnableOption (mdDoc "metrics");

        port = mkOption {
          type = types.port;
          default = 4444;
          description = mdDoc "The metrics port";
        };

        host = mkOption {
          type = types.str;
          default = "localhost";
          description = mdDoc "The mertrics host";
        };
      };

      sentry = {
        enable = mkEnableOption (mdDoc "sentry");

        dsn = mkOption {
          type = types.str;
          description = mdDoc "The Sentry/Glitchtip DSN";
        };

        environment = mkOption {
          type = types.str;
          description = mdDoc "The Sentry environment";
        };
      };
    };
  };

  config =
    mkIf cfg.enable
    {
      # Assertion to ensure at least one key method is provided
      assertions = [
        {
          assertion = cfg.eth.private-key-file != null || cfg.eth.private-key != null;
          message = "Either services.mm-relay.eth.private-key-file or services.mm-relay.eth.private-key must be set";
        }
      ];

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
            SENTRY_DSN = optionalString (cfg.sentry.enable or false) cfg.sentry.dsn;
            SENTRY_ENVIRONMENT = optionalString (cfg.sentry.enable or false) cfg.sentry.environment;
            KICK_TIMEOUT = cfg.kick-timeout;
            PING_INTERVAL = cfg.ping-interval;
          }
          // (
            if cfg.eth.private-key != null
            then {ETH_PRIVATE_KEY = cfg.eth.private-key;}
            else {ETH_PRIVATE_KEY_FILE = cfg.eth.private-key-file;}
          )
          // optionalAttrs (cfg.pinata.enable == true) {
            PINATA_API_HOST = cfg.pinata.hostname;
            PINATA_JWT_FILE = cfg.pinata.key-file;
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
      services.caddy = mkIf cfg.https-termination {
        enable = mkDefault true;
        virtualHosts."${cfg.hostname}".extraConfig = ''
          reverse_proxy http://localhost:${builtins.toString cfg.port}
        '';
      };
    };
}
