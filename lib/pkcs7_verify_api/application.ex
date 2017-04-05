defmodule PKCS7Verify do
  @moduledoc """
  This is an entry point of pkcs7_verify_api application.
  """

  use Application

  # See http://elixir-lang.org/docs/stable/elixir/Application.html
  # for more information on OTP Applications
  def start(_type, _args) do
    import Supervisor.Spec, warn: false

    # Define workers and child supervisors to be supervised
    children = [
      # Start the endpoint when the application starts
      supervisor(PKCS7Verify.Web.Endpoint, []),
      # Starts a worker by calling: PKCS7Verify.Worker.start_link(arg1, arg2, arg3)
      # worker(PKCS7Verify.Worker, [arg1, arg2, arg3]),
    ]

    # See http://elixir-lang.org/docs/stable/elixir/Supervisor.html
    # for other strategies and supported options
    opts = [strategy: :one_for_one, name: PKCS7Verify.Supervisor]
    Supervisor.start_link(children, opts)
  end

  # Tell Phoenix to update the endpoint configuration
  # whenever the application is updated.
  def config_change(changed, _new, removed) do
    PKCS7Verify.Web.Endpoint.config_change(changed, removed)
    :ok
  end
end
