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
      type: type,
      values: values
    }
  end
end
