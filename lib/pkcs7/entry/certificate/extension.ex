defmodule PKCS7.Entry.Certificate.Extension do
  defstruct id: nil,         # id_extensions() | oid()
            critical?: nil,  # boolean()
            value: nil       # der_encoded()

  def from_record({:Extension, id, critical?, value}) do
    %__MODULE__{
      id: PKCS7.oid_to_atom(id),
      critical?: critical?,
      value: value
    }
  end
end
