defmodule BlocknetNif.MixProject do
  use Mix.Project

  def project do
    [
      app: :blocknet_nif,
      version: "0.1.0",
      elixir: "~> 1.15",
      elixirc_paths: if(Mix.env() == :test, do: ["lib", "test/support"], else: ["lib"]),
      deps: [{:rustler, "== 0.37.3"}, {:jason, "~> 1.4"}],
      aliases: [
        precommit: [
          "format --check-formatted",
          "compile --force --warnings-as-errors",
          "test --warnings-as-errors"
        ]
      ]
    ]
  end

  def cli, do: [preferred_envs: [precommit: :test]]
  def application, do: [extra_applications: [:crypto, :logger]]
end
