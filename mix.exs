defmodule ChainNifs.MixProject do
  use Mix.Project

  def project do
    [
      app: :chain_nifs_tools,
      version: "0.1.0",
      elixir: "~> 1.15",
      elixirc_paths: [],
      deps: [],
      aliases: [precommit: &precommit/1]
    ]
  end

  defp precommit(args) do
    Mix.Task.run("format", ["--check-formatted"])
    Mix.Task.run("cmd", ["bin/check" | args])
  end
end
