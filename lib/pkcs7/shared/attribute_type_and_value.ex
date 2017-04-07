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
      type: get_type(type),
      value: value
    }
  end

  def get_type({2, 5, 4, 3}),
    do: :'commonName'
  def get_type({2, 5, 4, 4}),
    do: :'surname'
  def get_type({2, 5, 4, 6}),
    do: :'countryName'
  def get_type({2, 5, 4, 7}),
    do: :'localityName'
  def get_type({2, 5, 4, 8}),
    do: :'stateOrProvinceName'
  def get_type({2, 5, 4, 10}),
    do: :'organizationName'
  def get_type({2, 5, 4, 11}),
    do: :'organizationalUnitName'
  def get_type({2, 5, 4, 12}),
    do: :'title'
  def get_type({2, 5, 4, 41}),
    do: :'name'
  def get_type({2, 5, 4, 42}),
    do: :'givenName'
  def get_type({2, 5, 4, 43}),
    do: :'initials'
  def get_type({2, 5, 4, 44}),
    do: :'generationQualifier'
  def get_type({2, 5, 4, 46}),
    do: :'dnQualifier'
end
