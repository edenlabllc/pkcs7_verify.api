defmodule PKCS7.Entry.Content do
  defstruct id: nil,   # ?
            value: nil # binary

  def from_record({:ContentInfo, id, value}) do
    %__MODULE__{id: id, value: value}
  end
end
