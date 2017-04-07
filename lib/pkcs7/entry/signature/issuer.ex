defmodule PKCS7.Entry.Signature.Issuer do
  defstruct issuer: nil,
            serial_number: nil

  def from_record({:IssuerAndSerialNumber, issuer, serial_number}) do
    %__MODULE__{
      issuer: PKCS7.Shared.AttributeTypeAndValue.from_sequence(issuer),
      serial_number: serial_number
    }
  end
end
