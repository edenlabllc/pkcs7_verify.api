defmodule PKCS7 do
  alias :public_key, as: PublicKey

  def decode(binary_content) do
    binary_content
    |> PublicKey.pem_decode()
    |> Enum.map(&decode_entry/1)
    |> Enum.map(&PKCS7.Entry.from_record/1)
  end

  defp decode_entry({:ContentInfo, _der, :not_encrypted} = entry) do
    PublicKey.pem_entry_decode(entry)
  end

  def verify_signature(%PKCS7.Entry{} = entry) do
    IO.inspect entry
    message = entry.content.value
    cert = Enum.at(entry.certificates, 0)
    public_key = cert.certificate.subject_public_key_info.subject_public_key

    sign = Enum.at(entry.signatures, 0)
    signature = sign.content

    # IO.inspect PublicKey.verify(message, :sha1, signature, public_key)
  end

  def verify_signature(message, digest_type, signature, key) do
    PublicKey.verify(message, digest_type, signature, key)
  end
end
