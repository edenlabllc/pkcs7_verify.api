defmodule PKCS7.Entry.Digest do
  defstruct type: nil,      # ?
            algorythm: nil  # ?

  def from_set({:daSet, []}),
    do: []
  def from_set({:daSet, digests}) do
    digests
    |> Enum.map(&from_record/1)
  end

  def from_record({:DigestAlgorithmIdentifier, type, algorythm}) do
    %__MODULE__{
      type: PKCS7.oid_to_atom(type),
      algorythm: algorythm
    }
  end
end
