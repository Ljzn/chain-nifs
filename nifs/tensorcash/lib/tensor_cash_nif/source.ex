defmodule TensorCashNif.Source do
  @moduledoc false
  @submodule "liboqs-upstream"
  @files ["CMakeLists.txt", "src/sig/ml_dsa/pqcrystals-dilithium-standard_ml-dsa-65_ref/sign.c"]

  def prepare!(root) do
    root = Path.expand(root)
    vendor = Path.join(root, "vendor/liboqs")

    case git(root, ["rev-parse", "--show-toplevel"]) do
      {output, 0} ->
        repo = String.trim(output)
        prefix = String.trim(git!(root, ["rev-parse", "--show-prefix"]))

        if prefix == "nifs/tensorcash/" do
          path = prefix <> "vendor/liboqs"
          prepare_checkout!(repo, Path.join(repo, path), path)
        else
          require_sources!(vendor)
        end

      _ ->
        require_sources!(vendor)
    end

    :ok
  end

  defp prepare_checkout!(repo, vendor, path) do
    case git(repo, ["ls-tree", "HEAD", "--", path]) do
      {"160000 commit " <> entry, 0} ->
        [revision, recorded_path] = String.split(String.trim_trailing(entry), "	", parts: 2)
        if recorded_path != path, do: fail!("unexpected liboqs gitlink path")
        prepare_submodule!(repo, vendor, path, revision)

      _ ->
        # Source archives may be unpacked inside another Git repository.
        # Never initialize submodules in that unrelated enclosing repository.
        require_sources!(vendor)
    end
  end

  defp prepare_submodule!(repo, vendor, path, revision) do
    index = git!(repo, ["ls-files", "--stage", "--", path])

    if String.trim_trailing(index, "\n") != "160000 #{revision} 0\t#{path}" do
      fail!("liboqs HEAD/index gitlink mismatch; commit or restore the staged gitlink first")
    end

    case git(repo, ["diff", "--quiet", "HEAD", "--", ".gitmodules"]) do
      {_, 0} -> :ok
      _ -> fail!("modified .gitmodules; commit or restore its source configuration first")
    end

    modules_path =
      git!(repo, ["config", "--blob", "HEAD:.gitmodules", "--get", "submodule.#{@submodule}.path"])

    if String.trim(modules_path) != path,
      do: fail!("liboqs .gitmodules path does not match its gitlink")

    initialized? = File.exists?(Path.join(vendor, ".git"))

    current =
      if initialized? do
        ensure_clean!(vendor)
        git!(vendor, ["rev-parse", "HEAD"]) |> String.trim()
      else
        if File.dir?(vendor) and File.ls!(vendor) != [] do
          fail!("liboqs source has no submodule metadata; refusing to overwrite existing files")
        end

        nil
      end

    if current != revision or not complete?(vendor) do
      git!(repo, [
        "-c",
        "submodule.#{@submodule}.active=true",
        "submodule",
        "update",
        "--init",
        "--recursive",
        "--checkout",
        "--depth=1",
        "--",
        path
      ])
    end

    ensure_clean!(vendor)

    if String.trim(git!(vendor, ["rev-parse", "HEAD"])) != revision do
      fail!("liboqs checkout does not match the locked gitlink #{revision}")
    end

    require_sources!(vendor)
  end

  defp ensure_clean!(vendor) do
    if String.trim(git!(vendor, ["rev-parse", "--show-toplevel"])) != vendor do
      fail!("liboqs is not an independent submodule checkout")
    end

    if git!(vendor, ["status", "--porcelain", "--untracked-files=all"]) != "" do
      fail!("modified liboqs source; refusing to overwrite local changes")
    end
  end

  defp require_sources!(vendor) do
    unless complete?(vendor) do
      fail!(
        "missing liboqs source in #{vendor}; use a Git checkout with its locked submodule or a complete vendored source archive"
      )
    end

    :ok
  end

  defp complete?(vendor), do: Enum.all?(@files, &File.regular?(Path.join(vendor, &1)))

  defp git(root, args) do
    case System.find_executable("git") do
      nil ->
        {"git executable is unavailable", 127}

      executable ->
        System.cmd(executable, ["-c", "core.quotePath=false", "-C", root | args],
          stderr_to_stdout: true,
          env: Enum.map(~w(GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_COMMON_DIR), &{&1, nil})
        )
    end
  end

  defp git!(root, args) do
    case git(root, args) do
      {output, 0} ->
        output

      {output, code} ->
        fail!("Git source preparation failed (exit #{code}): #{String.slice(output, 0, 2000)}")
    end
  end

  defp fail!(message), do: raise(ArgumentError, "tensorcash_nif: source preparation: #{message}")
end
