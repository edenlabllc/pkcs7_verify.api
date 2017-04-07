defmodule PKCS7.Entry.Certificate.Extension do
  defstruct id: nil,         # id_extensions() | oid()
            critical?: nil,  # boolean()
            value: nil       # der_encoded()

  def from_record({:Extension, id, critical?, value}) do
    %__MODULE__{
      id: get_name(id),
      critical?: critical?,
      value: value
    }
  end

  def get_name({2, 5, 29}),
    do: :'ce'
  def get_name({2, 5, 29, 9}),
    do: :'subjectDirectoryAttributes'
  def get_name({2, 5, 29, 14}),
    do: :'subjectKeyIdentifier'
  def get_name({2, 5, 29, 15}),
    do: :'keyUsage'
  def get_name({2, 5, 29, 16}),
    do: :'privateKeyUsagePeriod'
  def get_name({2, 5, 29, 17}),
    do: :'subjectAltName'
  def get_name({2, 5, 29, 18}),
    do: :'issuerAltName'
  def get_name({2, 5, 29, 19}),
    do: :'basicConstraints'
  def get_name({2, 5, 29, 20}),
    do: :'cRLNumber'
  def get_name({2, 5, 29, 21}),
    do: :'reasonCode'
  def get_name({2, 5, 29, 23}),
    do: :'instructionCode'
  def get_name({2, 5, 29, 24}),
    do: :'invalidityDate'
  def get_name({2, 5, 29, 27}),
    do: :'deltaCRLIndicator'
  def get_name({2, 5, 29, 28}),
    do: :'issuingDistributionPoint'
  def get_name({2, 5, 29, 29}),
    do: :'certificateIssuer'
  def get_name({2, 5, 29, 30}),
    do: :'nameConstraints'
  def get_name({2, 5, 29, 31}),
    do: :'cRLDistributionPoints'
  def get_name({2, 5, 29, 32}),
    do: :'certificatePolicies'
  def get_name({2, 5, 29, 33}),
    do: :'policyMappings'
  def get_name({2, 5, 29, 35}),
    do: :'authorityKeyIdentifier'
  def get_name({2, 5, 29, 36}),
    do: :'policyConstraints'
  def get_name({2, 5, 29, 37}),
    do: :'extKeyUsage'
end
