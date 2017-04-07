defmodule PKCS7 do
  alias :public_key, as: PublicKey

  def decode(binary_content) do
    binary_content
    |> PublicKey.pem_decode()
    |> Enum.map(&decode_entry/1)
    |> Enum.map(&PKCS7.Entry.from_record/1)
  end

  defp decode_entry({:ContentInfo, _der, :not_encrypted} = entry) do
    PublicKey.pem_entry_decode(entry)
  end

  def verify_signature(%PKCS7.Entry{} = entry) do
    IO.inspect entry
    message = entry.content.value
    cert = Enum.at(entry.certificates, 0)
    public_key = cert.certificate.subject_public_key_info.subject_public_key

    sign = Enum.at(entry.signatures, 0)
    signature = sign.content

    IO.inspect PublicKey.verify(message, :sha1, signature, public_key)
  end


  def oid_to_atom({1, 2, 840, 113549, 1, 7, 2}),
    do: :'signedData'
  def oid_to_atom({2, 5, 4, 3}),
    do: :'commonName'
  def oid_to_atom({2, 5, 4, 4}),
    do: :'surname'
  def oid_to_atom({2, 5, 4, 6}),
    do: :'countryName'
  def oid_to_atom({2, 5, 4, 7}),
    do: :'localityName'
  def oid_to_atom({2, 5, 4, 8}),
    do: :'stateOrProvinceName'
  def oid_to_atom({2, 5, 4, 10}),
    do: :'organizationName'
  def oid_to_atom({2, 5, 4, 11}),
    do: :'organizationalUnitName'
  def oid_to_atom({2, 5, 4, 12}),
    do: :'title'
  def oid_to_atom({2, 5, 4, 41}),
    do: :'name'
  def oid_to_atom({2, 5, 4, 42}),
    do: :'givenName'
  def oid_to_atom({2, 5, 4, 43}),
    do: :'initials'
  def oid_to_atom({2, 5, 4, 44}),
    do: :'generationQualifier'
  def oid_to_atom({2, 5, 4, 46}),
    do: :'dnQualifier'
  def oid_to_atom({2, 5, 29, 24}),
    do: :'id-ce-invalidityDate'
  def oid_to_atom({2, 2, 840, 10040, 2, 3}),
    do: :'id-holdinstruction-reject'
  def oid_to_atom({2, 2, 840, 10040, 2, 2}),
    do: :'id-holdinstruction-callissuer'
  def oid_to_atom({2, 2, 840, 10040, 2, 1}),
    do: :'id-holdinstruction-none'
  def oid_to_atom({2, 2, 840, 10040, 2}),
    do: :'holdInstruction'
  def oid_to_atom({2, 5, 29, 23}),
    do: :'id-ce-holdInstructionCode'
  def oid_to_atom({2, 5, 29, 29}),
    do: :'id-ce-certificateIssuer'
  def oid_to_atom({2, 5, 29, 21}),
    do: :'id-ce-cRLReasons'
  def oid_to_atom({2, 5, 29, 27}),
    do: :'id-ce-deltaCRLIndicator'
  def oid_to_atom({2, 5, 29, 28}),
    do: :'id-ce-issuingDistributionPoint'
  def oid_to_atom({2, 5, 29, 20}),
    do: :'id-ce-cRLNumber'
  def oid_to_atom({1, 3, 6, 1, 5, 5, 7, 1, 11}),
    do: :'id-pe-subjectInfoAccess'
  def oid_to_atom({1, 3, 6, 1, 5, 5, 7, 1, 1}),
    do: :'id-pe-authorityInfoAccess'
  def oid_to_atom({2, 5, 29, 46}),
    do: :'id-ce-freshestCRL'
  def oid_to_atom({2, 5, 29, 54}),
    do: :'id-ce-inhibitAnyPolicy'
  def oid_to_atom({1, 3, 6, 1, 5, 5, 7, 3, 9}),
    do: :'id-kp-OCSPSigning'
  def oid_to_atom({1, 3, 6, 1, 5, 5, 7, 3, 8}),
    do: :'id-kp-timeStamping'
  def oid_to_atom({1, 3, 6, 1, 5, 5, 7, 3, 4}),
    do: :'id-kp-emailProtection'
  def oid_to_atom({1, 3, 6, 1, 5, 5, 7, 3, 3}),
    do: :'id-kp-codeSigning'
  def oid_to_atom({1, 3, 6, 1, 5, 5, 7, 3, 2}),
    do: :'id-kp-clientAuth'
  def oid_to_atom({1, 3, 6, 1, 5, 5, 7, 3, 1}),
    do: :'id-kp-serverAuth'
  def oid_to_atom({2, 5, 29, 37, 0}),
    do: :'anyExtendedKeyUsage'
  def oid_to_atom({2, 5, 29, 37}),
    do: :'id-ce-extKeyUsage'
  def oid_to_atom({2, 5, 29, 31}),
    do: :'id-ce-cRLDistributionPoints'
  def oid_to_atom({2, 5, 29, 36}),
    do: :'id-ce-policyConstraints'
  def oid_to_atom({2, 5, 29, 30}),
    do: :'id-ce-nameConstraints'
  def oid_to_atom({2, 5, 29, 19}),
    do: :'id-ce-basicConstraints'
  def oid_to_atom({2, 5, 29, 9}),
    do: :'id-ce-subjectDirectoryAttributes'
  def oid_to_atom({2, 5, 29, 18}),
    do: :'id-ce-issuerAltName'
  def oid_to_atom({2, 5, 29, 17}),
    do: :'id-ce-subjectAltName'
  def oid_to_atom({2, 5, 29, 33}),
    do: :'id-ce-policyMappings'
  def oid_to_atom({2, 5, 29, 32, 0}),
    do: :'anyPolicy'
  def oid_to_atom({2, 5, 29, 32}),
    do: :'id-ce-certificatePolicies'
  def oid_to_atom({2, 5, 29, 16}),
    do: :'id-ce-privateKeyUsagePeriod'
  def oid_to_atom({2, 5, 29, 15}),
    do: :'id-ce-keyUsage'
  def oid_to_atom({2, 5, 29, 14}),
    do: :'id-ce-subjectKeyIdentifier'
  def oid_to_atom({2, 5, 29, 35}),
    do: :'id-ce-authorityKeyIdentifier'
  def oid_to_atom({2, 5, 29}),
    do: :'id-ce'
  def oid_to_atom({2, 5, 1, 5, 55}),
    do: :'id-at-clearance'
  def oid_to_atom({2, 5, 4, 72}),
    do: :'id-at-role'
  def oid_to_atom({1, 3, 6, 1, 5, 5, 7, 10, 6}),
    do: :'id-aca-encAttrs'
  def oid_to_atom({1, 3, 6, 1, 5, 5, 7, 10, 4}),
    do: :'id-aca-group'
  def oid_to_atom({1, 3, 6, 1, 5, 5, 7, 10, 3}),
    do: :'id-aca-chargingIdentity'
  def oid_to_atom({1, 3, 6, 1, 5, 5, 7, 10, 2}),
    do: :'id-aca-accessIdentity'
  def oid_to_atom({1, 3, 6, 1, 5, 5, 7, 10, 1}),
    do: :'id-aca-authenticationInfo'
  def oid_to_atom({1, 3, 6, 1, 5, 5, 7, 10}),
    do: :'id-aca'
  def oid_to_atom({2, 5, 29, 55}),
    do: :'id-ce-targetInformation'
  def oid_to_atom({1, 3, 6, 1, 5, 5, 7, 1, 10}),
    do: :'id-pe-ac-proxying'
  def oid_to_atom({1, 3, 6, 1, 5, 5, 7, 1, 6}),
    do: :'id-pe-aaControls'
  def oid_to_atom({1, 3, 6, 1, 5, 5, 7, 1, 4}),
    do: :'id-pe-ac-auditIdentity'
  def oid_to_atom({1, 2, 840, 10045, 3, 1, 7}),
    do: :'prime256v1'
  def oid_to_atom({1, 2, 840, 10045, 3, 1, 6}),
    do: :'prime239v3'
  def oid_to_atom({1, 2, 840, 10045, 3, 1, 5}),
    do: :'prime239v2'
  def oid_to_atom({1, 2, 840, 10045, 3, 1, 4}),
    do: :'prime239v1'
  def oid_to_atom({1, 2, 840, 10045, 3, 1, 3}),
    do: :'prime192v3'
  def oid_to_atom({1, 2, 840, 10045, 3, 1, 2}),
    do: :'prime192v2'
  def oid_to_atom({1, 2, 840, 10045, 3, 1, 1}),
    do: :'prime192v1'
  def oid_to_atom({1, 2, 840, 10045, 3, 1}),
    do: :'primeCurve'
  def oid_to_atom({1, 2, 840, 10045, 3, 0, 20}),
    do: :'c2tnb431r1'
  def oid_to_atom({1, 2, 840, 10045, 3, 0, 19}),
    do: :'c2pnb368w1'
  def oid_to_atom({1, 2, 840, 10045, 3, 0, 18}),
    do: :'c2tnb359v1'
  def oid_to_atom({1, 2, 840, 10045, 3, 0, 17}),
    do: :'c2pnb304w1'
  def oid_to_atom({1, 2, 840, 10045, 3, 0, 16}),
    do: :'c2pnb272w1'
  def oid_to_atom({1, 2, 840, 10045, 3, 0, 15}),
    do: :'c2onb239v5'
  def oid_to_atom({1, 2, 840, 10045, 3, 0, 14}),
    do: :'c2onb239v4'
  def oid_to_atom({1, 2, 840, 10045, 3, 0, 13}),
    do: :'c2tnb239v3'
  def oid_to_atom({1, 2, 840, 10045, 3, 0, 12}),
    do: :'c2tnb239v2'
  def oid_to_atom({1, 2, 840, 10045, 3, 0, 11}),
    do: :'c2tnb239v1'
  def oid_to_atom({1, 2, 840, 10045, 3, 0, 10}),
    do: :'c2pnb208w1'
  def oid_to_atom({1, 2, 840, 10045, 3, 0, 9}),
    do: :'c2onb191v5'
  def oid_to_atom({1, 2, 840, 10045, 3, 0, 8}),
    do: :'c2onb191v4'
  def oid_to_atom({1, 2, 840, 10045, 3, 0, 7}),
    do: :'c2tnb191v3'
  def oid_to_atom({1, 2, 840, 10045, 3, 0, 6}),
    do: :'c2tnb191v2'
  def oid_to_atom({1, 2, 840, 10045, 3, 0, 5}),
    do: :'c2tnb191v1'
  def oid_to_atom({1, 2, 840, 10045, 3, 0, 4}),
    do: :'c2pnb176w1'
  def oid_to_atom({1, 2, 840, 10045, 3, 0, 3}),
    do: :'c2pnb163v3'
  def oid_to_atom({1, 2, 840, 10045, 3, 0, 2}),
    do: :'c2pnb163v2'
  def oid_to_atom({1, 2, 840, 10045, 3, 0, 1}),
    do: :'c2pnb163v1'
  def oid_to_atom({1, 2, 840, 10045, 3, 0}),
    do: :'c-TwoCurve'
  def oid_to_atom({1, 2, 840, 10045, 3}),
    do: :'ellipticCurve'
  def oid_to_atom({1, 2, 840, 10045, 2, 1}),
    do: :'id-ecPublicKey'
  def oid_to_atom({1, 2, 840, 10045, 2}),
    do: :'id-publicKeyType'
  def oid_to_atom({1, 2, 840, 10045, 1, 2, 3, 3}),
    do: :'ppBasis'
  def oid_to_atom({1, 2, 840, 10045, 1, 2, 3, 2}),
    do: :'tpBasis'
  def oid_to_atom({1, 2, 840, 10045, 1, 2, 3, 1}),
    do: :'gnBasis'
  def oid_to_atom({1, 2, 840, 10045, 1, 2, 3}),
    do: :'id-characteristic-two-basis'
  def oid_to_atom({1, 2, 840, 10045, 1, 2}),
    do: :'characteristic-two-field'
  def oid_to_atom({1, 2, 840, 10045, 1, 1}),
    do: :'prime-field'
  def oid_to_atom({1, 2, 840, 10045, 1}),
    do: :'id-fieldType'
  def oid_to_atom({1, 2, 840, 10045, 4, 1}),
    do: :'ecdsa-with-SHA1'
  def oid_to_atom({1, 2, 840, 10045, 4}),
    do: :'id-ecSigType'
  def oid_to_atom({1, 2, 840, 10045}),
    do: :'ansi-X9-62'
  def oid_to_atom({2, 16, 840, 1, 101, 2, 1, 1, 22}),
    do: :'id-keyExchangeAlgorithm'
  def oid_to_atom({1, 2, 840, 10046, 2, 1}),
    do: :'dhpublicnumber'
  def oid_to_atom({1, 2, 840, 10040, 4, 3}),
    do: :'id-dsa-with-sha1'
  def oid_to_atom({1, 2, 840, 10040, 4, 1}),
    do: :'id-dsa'
  def oid_to_atom({1, 2, 840, 113549, 1, 1, 8}),
    do: :'id-mgf1'
  def oid_to_atom({1, 2, 840, 113549, 2, 5}),
    do: :'id-md5'
  def oid_to_atom({1, 2, 840, 113549, 2, 2}),
    do: :'id-md2'
  def oid_to_atom({1, 3, 14, 3, 2, 26}),
    do: :'id-sha1'
  def oid_to_atom({1, 2, 840, 113549, 1, 1, 13}),
    do: :'sha512WithRSAEncryption'
  def oid_to_atom({1, 2, 840, 113549, 1, 1, 12}),
    do: :'sha384WithRSAEncryption'
  def oid_to_atom({1, 2, 840, 113549, 1, 1, 11}),
    do: :'sha256WithRSAEncryption'
  def oid_to_atom({1, 2, 840, 113549, 1, 1, 5}),
    do: :'sha1WithRSAEncryption'
  def oid_to_atom({1, 2, 840, 113549, 1, 1, 4}),
    do: :'md5WithRSAEncryption'
  def oid_to_atom({1, 2, 840, 113549, 1, 1, 2}),
    do: :'md2WithRSAEncryption'
  def oid_to_atom({1, 2, 840, 113549, 1, 1, 10}),
    do: :'id-RSASSA-PSS'
  def oid_to_atom({1, 2, 840, 113549, 1, 1, 9}),
    do: :'id-pSpecified'
  def oid_to_atom({1, 2, 840, 113549, 1, 1, 7}),
    do: :'id-RSAES-OAEP'
  def oid_to_atom({1, 2, 840, 113549, 1, 1, 1}),
    do: :'rsaEncryption'
  def oid_to_atom({1, 2, 840, 113549, 1, 1}),
    do: :'pkcs-1'
  def oid_to_atom(16),
    do: :'ub-x121-address-length'
  def oid_to_atom(180),
    do: :'ub-unformatted-address-length'
  def oid_to_atom(24),
    do: :'ub-terminal-id-length'
  def oid_to_atom(40),
    do: :'ub-surname-length'
  def oid_to_atom(128),
    do: :'ub-pseudonym'
  def oid_to_atom(16),
    do: :'ub-postal-code-length'
  def oid_to_atom(6),
    do: :'ub-pds-physical-address-lines'
  def oid_to_atom(30),
    do: :'ub-pds-parameter-length'
  def oid_to_atom(16),
    do: :'ub-pds-name-length'
  def oid_to_atom(4),
    do: :'ub-organizational-units'
  def oid_to_atom(32),
    do: :'ub-organizational-unit-name-length'
  def oid_to_atom(64),
    do: :'ub-organization-name-length'
  def oid_to_atom(32),
    do: :'ub-numeric-user-id-length'
  def oid_to_atom(256),
    do: :'ub-integer-options'
  def oid_to_atom(5),
    do: :'ub-initials-length'
  def oid_to_atom(16),
    do: :'ub-given-name-length'
  def oid_to_atom(3),
    do: :'ub-generation-qualifier-length'
  def oid_to_atom(40),
    do: :'ub-e163-4-sub-address-length'
  def oid_to_atom(15),
    do: :'ub-e163-4-number-length'
  def oid_to_atom(256),
    do: :'ub-extension-attributes'
  def oid_to_atom(16),
    do: :'ub-domain-name-length'
  def oid_to_atom(128),
    do: :'ub-domain-defined-attribute-value-length'
  def oid_to_atom(8),
    do: :'ub-domain-defined-attribute-type-length'
  def oid_to_atom(4),
    do: :'ub-domain-defined-attributes'
  def oid_to_atom(3),
    do: :'ub-country-name-numeric-length'
  def oid_to_atom(2),
    do: :'ub-country-name-alpha-length'
  def oid_to_atom(64),
    do: :'ub-common-name-length'
  def oid_to_atom(128),
    do: :'ub-emailaddress-length'
  def oid_to_atom(128),
    do: :'ub-match'
  def oid_to_atom(64),
    do: :'ub-serial-number'
  def oid_to_atom(64),
    do: :'ub-title'
  def oid_to_atom(64),
    do: :'ub-organizational-unit-name'
  def oid_to_atom(64),
    do: :'ub-organization-name'
  def oid_to_atom(128),
    do: :'ub-state-name'
  def oid_to_atom(128),
    do: :'ub-locality-name'
  def oid_to_atom(64),
    do: :'ub-common-name'
  def oid_to_atom(32768),
    do: :'ub-name'
  def oid_to_atom(6),
    do: :'teletex-domain-defined-attributes'
  def oid_to_atom(23),
    do: :'terminal-type'
  def oid_to_atom(22),
    do: :'extended-network-address'
  def oid_to_atom(21),
    do: :'local-postal-attributes'
  def oid_to_atom(20),
    do: :'unique-postal-name'
  def oid_to_atom(19),
    do: :'poste-restante-address'
  def oid_to_atom(18),
    do: :'post-office-box-address'
  def oid_to_atom(17),
    do: :'street-address'
  def oid_to_atom(16),
    do: :'unformatted-postal-address'
  def oid_to_atom(15),
    do: :'extension-physical-delivery-address-components'
  def oid_to_atom(14),
    do: :'physical-delivery-organization-name'
  def oid_to_atom(13),
    do: :'physical-delivery-personal-name'
  def oid_to_atom(12),
    do: :'extension-OR-address-components'
  def oid_to_atom(11),
    do: :'physical-delivery-office-number'
  def oid_to_atom(10),
    do: :'physical-delivery-office-name'
  def oid_to_atom(9),
    do: :'postal-code'
  def oid_to_atom(8),
    do: :'physical-delivery-country-name'
  def oid_to_atom(7),
    do: :'pds-name'
  def oid_to_atom(5),
    do: :'teletex-organizational-unit-names'
  def oid_to_atom(4),
    do: :'teletex-personal-name'
  def oid_to_atom(3),
    do: :'teletex-organization-name'
  def oid_to_atom(2),
    do: :'teletex-common-name'
  def oid_to_atom(1),
    do: :'common-name'
  def oid_to_atom({1, 2, 840, 113549, 1, 9, 1}),
    do: :'id-emailAddress'
  def oid_to_atom({1, 2, 840, 113549, 1, 9}),
    do: :'pkcs-9'
  def oid_to_atom({0, 9, 2342, 19200300, 100, 1, 25}),
    do: :'id-domainComponent'
  def oid_to_atom({2, 5, 4, 65}),
    do: :'id-at-pseudonym'
  def oid_to_atom({2, 5, 4, 5}),
    do: :'id-at-serialNumber'
  def oid_to_atom({2, 5, 4, 6}),
    do: :'id-at-countryName'
  def oid_to_atom({2, 5, 4, 46}),
    do: :'id-at-dnQualifier'
  def oid_to_atom({2, 5, 4, 12}),
    do: :'id-at-title'
  def oid_to_atom({2, 5, 4, 11}),
    do: :'id-at-organizationalUnitName'
  def oid_to_atom({2, 5, 4, 10}),
    do: :'id-at-organizationName'
  def oid_to_atom({2, 5, 4, 8}),
    do: :'id-at-stateOrProvinceName'
  def oid_to_atom({2, 5, 4, 7}),
    do: :'id-at-localityName'
  def oid_to_atom({2, 5, 4, 3}),
    do: :'id-at-commonName'
  def oid_to_atom({2, 5, 4, 44}),
    do: :'id-at-generationQualifier'
  def oid_to_atom({2, 5, 4, 43}),
    do: :'id-at-initials'
  def oid_to_atom({2, 5, 4, 42}),
    do: :'id-at-givenName'
  def oid_to_atom({2, 5, 4, 4}),
    do: :'id-at-surname'
  def oid_to_atom({2, 5, 4, 41}),
    do: :'id-at-name'
  def oid_to_atom({2, 5, 4}),
    do: :'id-at'
  def oid_to_atom({1, 3, 6, 1, 5, 5, 7, 48, 5}),
    do: :'id-ad-caRepository'
  def oid_to_atom({1, 3, 6, 1, 5, 5, 7, 48, 3}),
    do: :'id-ad-timeStamping'
  def oid_to_atom({1, 3, 6, 1, 5, 5, 7, 48, 2}),
    do: :'id-ad-caIssuers'
  def oid_to_atom({1, 3, 6, 1, 5, 5, 7, 48, 1}),
    do: :'id-ad-ocsp'
  def oid_to_atom({1, 3, 6, 1, 5, 5, 7, 2, 2}),
    do: :'id-qt-unotice'
  def oid_to_atom({1, 3, 6, 1, 5, 5, 7, 2, 1}),
    do: :'id-qt-cps'
  def oid_to_atom({1, 3, 6, 1, 5, 5, 7, 48}),
    do: :'id-ad'
  def oid_to_atom({1, 3, 6, 1, 5, 5, 7, 3}),
    do: :'id-kp'
  def oid_to_atom({1, 3, 6, 1, 5, 5, 7, 2}),
    do: :'id-qt'
  def oid_to_atom({1, 3, 6, 1, 5, 5, 7, 1}),
    do: :'id-pe'
  def oid_to_atom({1, 3, 6, 1, 5, 5, 7}),
    do: :'id-pkix'
  def oid_to_atom({1, 3}),
    do: :'identified-organization'
  def oid_to_atom({1, 3, 14}),
    do: :'oiw'
  def oid_to_atom({1, 3, 14, 3}),
    do: :'secsig'
  def oid_to_atom({1, 3, 14, 3, 2}),
    do: :'algorithm'
  def oid_to_atom({1, 3, 14, 3, 2, 26}),
    do: :'sha1'
  def oid_to_atom({1, 3, 14, 3, 2, 7}),
    do: :'desCBC'
  def oid_to_atom({1, 2, 840, 113549, 3, 10}),
    do: :'desCDMF'
  def oid_to_atom({1, 2, 840, 113549, 1, 9}),
    do: :'pkcs-9'
  def oid_to_atom({1, 2, 840, 113549, 1, 9, 1}),
    do: :'emailAddress'
  def oid_to_atom({1, 2, 840, 113549, 1, 9, 2}),
    do: :'unstructuredName'
  def oid_to_atom({1, 2, 840, 113549, 1, 9, 3}),
    do: :'contentType'
  def oid_to_atom({1, 2, 840, 113549, 1, 9, 4}),
    do: :'messageDigest'
  def oid_to_atom({1, 2, 840, 113549, 1, 9, 5}),
    do: :'signingTime'
  def oid_to_atom({1, 2, 840, 113549, 1, 9, 6}),
    do: :'countersignature'
  def oid_to_atom({1, 2, 840, 113549, 1, 9, 7}),
    do: :'challengePassword'
  def oid_to_atom({1, 2, 840, 113549, 1, 9, 8}),
    do: :'unstructuredAddress'
  def oid_to_atom({1, 2, 840, 113549, 1, 9, 9}),
    do: :'extendedCertificateAttributes'
  def oid_to_atom({1, 2, 840, 113549, 1, 9, 15}),
    do: :'smimeCapabilities'
  def id_to_atom({2, 5, 29}),
    do: :'ce'
  def id_to_atom({2, 5, 29, 9}),
    do: :'subjectDirectoryAttributes'
  def id_to_atom({2, 5, 29, 14}),
    do: :'subjectKeyIdentifier'
  def id_to_atom({2, 5, 29, 15}),
    do: :'keyUsage'
  def id_to_atom({2, 5, 29, 16}),
    do: :'privateKeyUsagePeriod'
  def id_to_atom({2, 5, 29, 17}),
    do: :'subjectAltName'
  def id_to_atom({2, 5, 29, 18}),
    do: :'issuerAltName'
  def id_to_atom({2, 5, 29, 19}),
    do: :'basicConstraints'
  def id_to_atom({2, 5, 29, 20}),
    do: :'cRLNumber'
  def id_to_atom({2, 5, 29, 21}),
    do: :'reasonCode'
  def id_to_atom({2, 5, 29, 23}),
    do: :'instructionCode'
  def id_to_atom({2, 5, 29, 24}),
    do: :'invalidityDate'
  def id_to_atom({2, 5, 29, 27}),
    do: :'deltaCRLIndicator'
  def id_to_atom({2, 5, 29, 28}),
    do: :'issuingDistributionPoint'
  def id_to_atom({2, 5, 29, 29}),
    do: :'certificateIssuer'
  def id_to_atom({2, 5, 29, 30}),
    do: :'nameConstraints'
  def id_to_atom({2, 5, 29, 31}),
    do: :'cRLDistributionPoints'
  def id_to_atom({2, 5, 29, 32}),
    do: :'certificatePolicies'
  def id_to_atom({2, 5, 29, 33}),
    do: :'policyMappings'
  def id_to_atom({2, 5, 29, 35}),
    do: :'authorityKeyIdentifier'
  def id_to_atom({2, 5, 29, 36}),
    do: :'policyConstraints'
  def id_to_atom({2, 5, 29, 37}),
    do: :'extKeyUsage'
end
