defmodule PKCS7.Entry.Certificate do
  defstruct certificate: nil,           # %PKCS7.Entry.Certificates.TBS{}
            signature_algorythm: nil,   # %PKCS7.Shared.AlgorithmIdentifier{}
            signature: nil              # binary

  def from_set({:certSet, []}),
    do: []
  def from_set({:certSet, certificates}) when is_list(certificates) do
    certificates
    |> Enum.map(&from_record/1)
  end

  def from_record({:certificate, certificate}) do
    from_record(certificate)
  end
  def from_record({:Certificate, certificate, signature_algorythm, signature}) do
    %__MODULE__{
      signature: signature,
      certificate: PKCS7.Entry.Certificates.TBS.from_record(certificate),
      signature_algorythm: PKCS7.Shared.AlgorithmIdentifier.from_record(signature_algorythm)}
  end
end
