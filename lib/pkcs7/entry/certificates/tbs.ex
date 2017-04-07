defmodule PKCS7.Entry.Certificates.TBS do
  defstruct version: nil,                 # v1 | v2 | v3
            serial_number: nil,           # integer()
            signature: nil,               # %PKCS7.Shared.AlgorithmIdentifier{}
            issuer: nil,                  # [%PKCS7.Shared.AttributeTypeAndValue{}]
            validity: nil,                # %PKCS7.Entry.Certificate.Validity{}
            subject: nil,                 # [%PKCS7.Shared.AttributeTypeAndValue{}]
            subject_public_key_info: nil, # %PKCS7.Entry.Certificate.SubjectPublicKeyInfo{}
            issuer_unique_id: nil,        # binary | asn1_novalue
            subject_unique_id: nil,       # binary | asn1_novalue
            extensions: []                # [%PKCS7.Entry.Certificate.Extension{}]

  def from_record({:TBSCertificate, version, serial_number, signature, issuer, validity, subject,
                                    subject_public_key_info, issuer_unique_id, subject_unique_id, extensions}) do
    %__MODULE__{
      version: version,
      serial_number: serial_number,
      signature: PKCS7.Shared.AlgorithmIdentifier.from_record(signature),
      issuer: PKCS7.Shared.AttributeTypeAndValue.from_sequence(issuer),
      validity: PKCS7.Entry.Certificate.Validity.from_record(validity),
      subject: PKCS7.Shared.AttributeTypeAndValue.from_sequence(subject),
      subject_public_key_info: PKCS7.Entry.Certificate.SubjectPublicKeyInfo.from_record(subject_public_key_info),
      issuer_unique_id: issuer_unique_id,
      subject_unique_id: subject_unique_id,
      extensions: Enum.map(extensions, &PKCS7.Entry.Certificate.Extension.from_record/1)
    }
  end
end
