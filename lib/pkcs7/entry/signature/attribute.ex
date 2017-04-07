defmodule PKCS7.Entry.Signature.Attribute do
  defstruct type: nil,
            values: nil

  def from_set({:aaSet, []}),
    do: []
  def from_set({:aaSet, signatures}) when is_list(signatures) do
    signatures
    |> Enum.map(&from_record/1)
  end

  def from_record({:"AttributePKCS-7", type, values}) do
    %__MODULE__{
      type: PKCS7.oid_to_atom(type),
      values: values |> Enum.map(&value/1)
    }
  end

  def value({1, 2, 840, 113549, 1, 7, 1}),
    do: :'data'
  # def value(<<codepoints::binary>>) do
  #   codepoints
  #   |> String.codepoints()
  #   |> Enum.join()
  # end
  def value(val),
    do: val
end
