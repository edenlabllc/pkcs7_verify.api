use Mix.Releases.Config,
  default_release: :default,
  default_environment: :default

cookie = :sha256
|> :crypto.hash(System.get_env("ERLANG_COOKIE") || "KQqI4Y5oGDcWxSH79W5LEoTb7i4nV9gg8PJ25YmHWgMAqO9eTl75zvkhMbCiksBd")
|> Base.encode64

environment :default do
  set pre_start_hook: "bin/hooks/pre-start.sh"
  set dev_mode: false
  set include_erts: false
  set include_src: false
  set cookie: cookie
end

release :pkcs7_verify_api do
  set version: current_version(:pkcs7_verify_api)
  set applications: [
    pkcs7_verify_api: :permanent
  ]
end
