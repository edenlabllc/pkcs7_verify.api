defmodule PKCS7.Shared.AttributeTypeAndValue do
  defstruct type: nil,   # id_attributes()
            value: nil   # term()

  def from_sequence({:rdnSequence, []}),
    do: []
  def from_sequence({:rdnSequence, signatures}) when is_list(signatures) do
    signatures
    |> Enum.map(&from_record/1)
  end

  def from_record([{:AttributeTypeAndValue, type, value}]) do
    %__MODULE__{
      type: PKCS7.oid_to_atom(type),
      value: binary_to_string(value)
    }
  end

  def binary_to_string(<<20, 14, codepoints::binary>>) do
    codepoints
    |> String.codepoints()
    |> Enum.join()
  end
end
