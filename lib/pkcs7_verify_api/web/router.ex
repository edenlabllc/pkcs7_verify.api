defmodule PKCS7Verify.Web.Router do
  @moduledoc """
  The router provides a set of macros for generating routes
  that dispatch to specific controllers and actions.
  Those macros are named after HTTP verbs.

  More info at: https://hexdocs.pm/phoenix/Phoenix.Router.html
  """
  use PKCS7Verify.Web, :router

  pipeline :api do
    plug :accepts, ["json"]
    plug :put_secure_browser_headers

    # Uncomment to enable versioning of your API
    # plug Multiverse, gates: [
    #   "2016-07-31": PKCS7Verify.Web.InitialGate
    # ]

    # You can allow JSONP requests by uncommenting this line:
    # plug :allow_jsonp
  end

  scope "/", PKCS7Verify.Web do
    pipe_through :api

    get "/page", PageController, :index
  end
end
