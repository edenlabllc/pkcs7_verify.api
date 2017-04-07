defmodule PKCS7.Entry.Signature.DigestEncryptionAlgorithmIdentifier do
  defstruct algorithm: nil,  # %PKCS7.Shared.AlgorithmIdentifier{}
            parameters: nil  # binary

  def from_record({:DigestEncryptionAlgorithmIdentifier, algorithm, parameters}) do
    %__MODULE__{
      algorithm: PKCS7.Shared.AlgorithmIdentifier.oid_to_atom(algorithm),
      parameters: parameters
    }
  end
end
