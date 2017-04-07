defmodule PKCS7.Entry.Content do
  defstruct type: nil,   # ?
            value: nil # binary

  def from_record({:ContentInfo, type, value}) do
    %__MODULE__{
      type: PKCS7.Entry.Signature.Attribute.value(type),
      value: value
    }
  end
end
