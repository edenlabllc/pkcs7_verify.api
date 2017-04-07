defmodule PKCS7VerifyTest do
  use ExUnit.Case
  doctest PKCS7Verify
  alias :public_key, as: PublicKey

  test "the truth" do
    {:ok, p7} = File.read("test/fixtures/signed.p7")

    PKCS7.decode(p7)
    # |> Enum.map(&PKCS7.verify_signature/1)
    |> IO.inspect
  end
end
