defmodule PKCS7Verify.Web.PageController do
  @moduledoc """
  Sample controller for generated application.
  """
  use PKCS7Verify.Web, :controller

  action_fallback PKCS7Verify.Web.FallbackController

  def index(conn, _params) do
    render conn, "page.json"
  end
end
