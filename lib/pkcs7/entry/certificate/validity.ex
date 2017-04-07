defmodule PKCS7.Entry.Certificate.Validity do
  defstruct not_before: nil, # time()
            not_after: nil   # time()

  def from_record({:Validity, not_before, not_after}) do
    %__MODULE__{
      not_before: not_before,
      not_after: not_after
    }
  end
end
