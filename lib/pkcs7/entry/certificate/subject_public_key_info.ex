defmodule PKCS7.Entry.Certificate.SubjectPublicKeyInfo do
  defstruct algorithm: nil,         # %PKCS7.Shared.AlgorithmIdentifier{}
            subject_public_key: nil # binary()

  def from_record({:SubjectPublicKeyInfo, algorithm, subject_public_key}) do
    %__MODULE__{
      algorithm: PKCS7.Shared.AlgorithmIdentifier.from_record(algorithm),
      subject_public_key: subject_public_key
    }
  end
end
