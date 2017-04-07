defmodule PKCS7.Entry.Signature.DigestAlgorithmIdentifier do
  defstruct algorithm: nil,  # %PKCS7.Shared.AlgorithmIdentifier{}
            parameters: nil  # binary

  def from_record({:DigestAlgorithmIdentifier, algorithm, parameters}) do
    %__MODULE__{
      algorithm: PKCS7.Shared.AlgorithmIdentifier.oid_to_atom(algorithm),
      parameters: parameters
    }
  end
end
