defmodule PKCS7.Entry do
  defstruct id: nil,            # oid
            content: nil,       # %PKCS7.Entry.Content{}
            digests: [],        # %PKCS7.Entry.Digest{}
            certificates: [],   # %PKCS7.Entry.Certificate{}
            signatures: []      # %PKCS7.Entry.Signature{}

  def from_record({:ContentInfo, id, data}) do
    %__MODULE__{
      id: PKCS7.oid_to_atom(id)
    }
    |> put_entry_data(data)
  end

  defp put_entry_data(entry, {:SignedData, :sdVer1, digests_set, content, cert_set, :asn1_NOVALUE, signs_set}) do
    %{entry |
      content: PKCS7.Entry.Content.from_record(content),
      digests: PKCS7.Entry.Digest.from_set(digests_set),
      certificates: PKCS7.Entry.Certificate.from_set(cert_set),
      signatures: PKCS7.Entry.Signature.from_set(signs_set)
    }
  end
end
