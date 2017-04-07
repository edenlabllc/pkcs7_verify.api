defmodule PKCS7.Entry.Signature do
  defstruct issuer: nil,                       # %PKCS7.Entry.Signature.Issuer{}
            digest_algorythm: nil,             # %PKCS7.Entry.Signature.DigestAlgorithmIdentifier{}
            attributes: [],                    # [$PKCS7.Entry.Signature.Attribute{}]
            digest_encryption_algorythm: nil,  # %PKCS7.Entry.Signature.DigestEncryptionAlgorithmIdentifier{}
            content: nil                       # binary

  def from_set({:siSet, []}),
    do: []
  def from_set({:siSet, signatures}) when is_list(signatures) do
    signatures
    |> Enum.map(&from_record/1)
  end

  def from_record({:SignerInfo, :siVer1, issuer, dig_algo, attrs, dig_encryption_algo, content, :asn1_NOVALUE}) do
    %__MODULE__{
      issuer: PKCS7.Entry.Signature.Issuer.from_record(issuer),
      digest_algorythm: PKCS7.Entry.Signature.DigestAlgorithmIdentifier.from_record(dig_algo),
      attributes: PKCS7.Entry.Signature.Attribute.from_set(attrs),
      digest_encryption_algorythm: PKCS7.Entry.Signature.DigestEncryptionAlgorithmIdentifier.from_record(dig_encryption_algo),
      content: content
    }
  end
end

