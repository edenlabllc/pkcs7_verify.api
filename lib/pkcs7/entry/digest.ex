defmodule PKCS7.Entry.Digest do
  defstruct id: nil,        # ?
            algorythm: nil  # ?

  def from_set({:daSet, []}),
    do: []
  def from_set({:daSet, digests}) do
    digests
    |> Enum.map(&from_record/1)
  end

  def from_record({:DigestAlgorithmIdentifier, id, algorythm}) do
    %__MODULE__{
      id: get_algo(id),
      algorythm: get_algo(algorythm)
    }
  end

  def get_algo({1, 3}),
    do: :'identified-organization'
  def get_algo({1, 3, 14}),
    do: :'oiw'
  def get_algo({1, 3, 14, 3}),
    do: :'secsig'
  def get_algo({1, 3, 14, 3, 2}),
    do: :'algorithm'
  def get_algo({1, 3, 14, 3, 2, 26}),
    do: :'sha1'
  def get_algo({1, 3, 14, 3, 2, 7}),
    do: :'desCBC'
  def get_algo({1, 2, 840, 113549, 3, 10}),
    do: :'desCDMF'
  def get_algo({:asn1_OPENTYPE, _} = ot),
    do: ot
end
