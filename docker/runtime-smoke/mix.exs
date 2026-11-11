defmodule ChainNifsSmoke.MixProject do
  use Mix.Project

  def project do
    [app: :chain_nifs_smoke, version: "0.1.0", elixir: "~> 1.15", deps: deps()]
  end

  def application, do: [extra_applications: [:logger, :crypto]]

  defp deps do
    [
      {:parano1d_nif, path: "../../nifs/parano1d"},
      {:tensorcash_nif, path: "../../nifs/tensorcash"},
      {:blocknet_nif, path: "../../nifs/blocknet"}
    ]
  end
end
