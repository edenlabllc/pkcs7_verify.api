defmodule PKCS7.Shared.AlgorithmIdentifier do
  defstruct algorithm: nil, parameters: nil

  def from_record({:AlgorithmIdentifier, algorithm, parameters}) do
    %__MODULE__{
      algorithm: PKCS7.oid_to_atom(algorithm),
      parameters: parameters
    }
  end
end
