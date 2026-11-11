defmodule Parano1dNif.Precompiled do
  @moduledoc false
  @app :parano1d_nif
  @targets ~w(x86_64-unknown-linux-musl aarch64-unknown-linux-musl)

  def rustler_options!(root, env \\ System.get_env()) do
    case Map.get(env, "CHAIN_NIFS_MODE", "source") do
      "source" ->
        []

      "precompiled" ->
        host_target = host_target!()
        target = selected_target(env, host_target)
        resources = verify!(root, target, host_target, System.otp_release())

        [
          skip_compilation?: true,
          load_from: {@app, "priv/precompiled/#{target}/#{@app}"},
          external_resources: resources,
          load_data_fun: {__MODULE__, :load_data}
        ]

      other ->
        fail!("invalid CHAIN_NIFS_MODE #{inspect(other)}; expected source or precompiled")
    end
  end

  def selected_target(env, host_target), do: Map.get(env, "CHAIN_NIFS_TARGET") || host_target

  # Recheck the deployed environment and bytes before loading, without env variables.
  def load_data do
    target = host_target!()
    verify!(Application.app_dir(@app), target, target, System.otp_release())
    0
  end

  def host_target! do
    architecture = :erlang.system_info(:system_architecture) |> to_string()

    ldd =
      if :os.type() == {:unix, :linux} and not String.contains?(architecture, "musl") do
        case System.find_executable("ldd") do
          nil -> ""
          executable -> executable |> System.cmd(["--version"], stderr_to_stdout: true) |> elem(0)
        end
      else
        ""
      end

    detect_target!(architecture, :os.type(), ldd)
  end

  def detect_target!(architecture, os, ldd) do
    musl? = String.contains?(architecture, "musl") or String.contains?(ldd, "musl")

    cond do
      os != {:unix, :linux} or not musl? ->
        fail!("precompiled mode requires Linux musl; host is #{architecture}")

      String.starts_with?(architecture, "x86_64-") ->
        "x86_64-unknown-linux-musl"

      String.starts_with?(architecture, "aarch64-") ->
        "aarch64-unknown-linux-musl"

      true ->
        fail!("unsupported host architecture #{architecture}")
    end
  end

  # Explicit host inputs keep validation testable without mutating process-wide env.
  def verify!(root, target, host_target, otp_major) do
    unless target in @targets do
      fail!(
        "unsupported CHAIN_NIFS_TARGET #{inspect(target)}; expected #{Enum.join(@targets, " or ")}"
      )
    end

    if target != host_target, do: fail!("target #{target} does not match host #{host_target}")

    if to_string(otp_major) != "27",
      do: fail!("precompiled artifacts require OTP 27; got #{otp_major}")

    base = Path.join([root, "priv", "precompiled", target])
    manifest_path = Path.join(base, "manifest.json")
    artifact_path = Path.join(base, "#{@app}.so")
    manifest = read!(manifest_path) |> Jason.decode!()

    expected = %{
      "schema_version" => 1,
      "project" => Atom.to_string(@app),
      "target" => target,
      "otp_major" => 27
    }

    Enum.each(expected, fn {key, value} ->
      if not is_map(manifest) or Map.get(manifest, key) !== value,
        do: fail!("manifest #{key} must be #{inspect(value)}")
    end)

    actual_sha = :crypto.hash(:sha256, read!(artifact_path)) |> Base.encode16(case: :lower)

    if Map.get(manifest, "sha256") != actual_sha,
      do: fail!("SHA-256 mismatch for #{artifact_path}")

    [manifest_path, artifact_path]
  end

  defp read!(path) do
    case File.read(path) do
      {:ok, bytes} -> bytes
      {:error, reason} -> fail!("cannot read #{path}: #{:file.format_error(reason)}")
    end
  end

  defp fail!(message),
    do: raise(ArgumentError, "#{@app}: #{message}; no source fallback or download")
end
