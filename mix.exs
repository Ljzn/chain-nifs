defmodule Parano1dNif.MixProject do
  use Mix.Project

  def project do
    [
      app: :parano1d_nif,
      version: "0.1.0",
      elixir: "~> 1.15",
      start_permanent: Mix.env() == :prod,
      elixirc_paths: elixirc_paths(Mix.env()),
      deps: [{:rustler, "== 0.37.3"}, {:jason, "~> 1.4"}],
      aliases: [precommit: ["format --check-formatted", "test"]]
    ]
  end

  def cli, do: [preferred_envs: [precommit: :test]]

  def application, do: [extra_applications: [:logger, :crypto]]
  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]
end
