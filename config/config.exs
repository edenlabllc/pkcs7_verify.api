# This file is responsible for configuring your application
# and its dependencies with the aid of the Mix.Config module.
use Mix.Config

# This configuration is loaded before any dependency and is restricted
# to this project. If another project depends on this project, this
# file won't be loaded nor affect the parent project. For this reason,
# if you want to provide default values for your application for
# 3rd-party users, it should be done in your "mix.exs" file.

# You can configure for your application as:
#
#     config :pkcs7_verify_api, key: :value
#
# And access this configuration in your application as:
#
#     Application.get_env(:pkcs7_verify_api, :key)
#
# Or configure a 3rd-party app:
#
#     config :logger, level: :info
#
# Or read environment variables in runtime (!) as:
#
#     :var_name, "${ENV_VAR_NAME}"

# This configuration file is loaded before any dependency and
# is restricted to this project.

# General application configuration

config :pkcs7_verify_api,
  namespace: PKCS7Verify

# Configures the endpoint
config :pkcs7_verify_api, PKCS7Verify.Web.Endpoint,
  url: [host: "localhost"],
  secret_key_base: "eH+2gMIjVHplWfVujmWshm+I6KGIrEX7qfSCYmDkC1e2uHd3r57+KtjBLlYEgMdt",
  render_errors: [view: EView.Views.PhoenixError, accepts: ~w(json)]

# Configures Elixir's Logger
config :logger, :console,
  format: "$time $metadata[$level] $message\n",
  metadata: [:request_id]

# It is also possible to import configuration files, relative to this
# directory. For example, you can emulate configuration per environment
# by uncommenting the line below and defining dev.exs, test.exs and such.
# Configuration from the imported file will override the ones defined
# here (which is why it is important to import them last).
#
import_config "#{Mix.env}.exs"
