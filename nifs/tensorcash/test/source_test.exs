defmodule TensorCashNif.SourceTest do
  use ExUnit.Case, async: false

  alias TensorCashNif.{Precompiled, Source}

  @vendor "nifs/tensorcash/vendor/liboqs"
  @sign "src/sig/ml_dsa/pqcrystals-dilithium-standard_ml-dsa-65_ref/sign.c"

  setup do
    old_protocol = System.get_env("GIT_ALLOW_PROTOCOL")
    System.put_env("GIT_ALLOW_PROTOCOL", "file")

    tmp =
      Path.join(
        System.tmp_dir!(),
        "tensorcash-source-#{System.unique_integer([:positive])} with spaces"
      )

    File.mkdir_p!(tmp)

    on_exit(fn ->
      if old_protocol,
        do: System.put_env("GIT_ALLOW_PROTOCOL", old_protocol),
        else: System.delete_env("GIT_ALLOW_PROTOCOL")

      File.rm_rf!(tmp)
    end)

    upstream = Path.join(tmp, "upstream")
    init_repo!(upstream)
    write_vendor!(upstream, "A")
    commit!(upstream, "source A")
    a = git!(upstream, ["rev-parse", "HEAD"])
    File.write!(Path.join(upstream, "revision.txt"), "B\n")
    commit!(upstream, "source B")
    b = git!(upstream, ["rev-parse", "HEAD"])

    monorepo = Path.join(tmp, "monorepo")
    init_repo!(monorepo)
    package = Path.join(monorepo, "nifs/tensorcash")
    File.mkdir_p!(package)
    File.write!(Path.join(package, "fixture.txt"), "source package\n")

    git!(monorepo, [
      "submodule",
      "add",
      "--name",
      "liboqs-upstream",
      "file://" <> URI.encode(upstream),
      @vendor
    ])

    git!(Path.join(monorepo, @vendor), ["checkout", "--detach", a])

    git!(monorepo, [
      "config",
      "--file",
      ".gitmodules",
      "submodule.parano1d-upstream.path",
      "nifs/parano1d/vendor/parano1d"
    ])

    git!(monorepo, [
      "config",
      "--file",
      ".gitmodules",
      "submodule.parano1d-upstream.url",
      Path.join(tmp, "missing-parano1d-remote")
    ])

    File.mkdir_p!(Path.join(monorepo, "nifs/parano1d/vendor/parano1d"))

    git!(monorepo, [
      "update-index",
      "--add",
      "--cacheinfo",
      "160000,#{a},nifs/parano1d/vendor/parano1d"
    ])

    commit!(monorepo, "pin only required source")

    assert git!(monorepo, ["ls-tree", "HEAD", "--", "nifs/parano1d/vendor/parano1d"]) ==
             "160000 commit #{a}\tnifs/parano1d/vendor/parano1d"

    consumer = Path.join(tmp, "consumer")
    git!(tmp, ["clone", "--no-recurse-submodules", monorepo, consumer])

    %{
      tmp: tmp,
      upstream: upstream,
      monorepo: monorepo,
      consumer: consumer,
      package: Path.join(consumer, "nifs/tensorcash"),
      vendor: Path.join(consumer, @vendor),
      a: a,
      b: b
    }
  end

  @tag :source_entrypoint
  test "the actual Rustler source-mode entry point prepares a fresh dependency", ctx do
    refute File.regular?(Path.join(ctx.vendor, "CMakeLists.txt"))
    assert Precompiled.rustler_options!(ctx.package, %{"CHAIN_NIFS_MODE" => "source"}) == []
    assert File.regular?(Path.join(ctx.vendor, "CMakeLists.txt"))
    assert git!(ctx.vendor, ["rev-parse", "HEAD"]) == ctx.a
    assert File.read!(Path.join(ctx.vendor, "revision.txt")) == "A\n"
    refute File.regular?(Path.join(ctx.consumer, "nifs/parano1d/vendor/parano1d/.git"))
  end

  test "sparse dependencies initialize liboqs without visiting the unrelated invalid remote",
       ctx do
    git!(ctx.consumer, ["sparse-checkout", "init", "--no-cone"])
    git!(ctx.consumer, ["sparse-checkout", "set", "/nifs/tensorcash/"])
    refute File.exists?(Path.join(ctx.consumer, ".gitmodules"))
    assert Source.prepare!(ctx.package) == :ok
    assert git!(ctx.vendor, ["rev-parse", "HEAD"]) == ctx.a
    assert File.regular?(Path.join(ctx.vendor, @sign))
    refute File.exists?(Path.join(ctx.consumer, ".git/modules/parano1d-upstream"))
  end

  test "complete correctly pinned vendor can be reused when its remote disappears", ctx do
    assert Source.prepare!(ctx.package) == :ok
    File.rename!(ctx.upstream, ctx.upstream <> "-offline")
    assert Source.prepare!(ctx.package) == :ok
    assert git!(ctx.vendor, ["rev-parse", "HEAD"]) == ctx.a
    assert File.read!(Path.join(ctx.vendor, "revision.txt")) == "A\n"
  end

  test "fresh inactive submodule with update disabled is still initialized explicitly", ctx do
    git!(ctx.consumer, ["config", "submodule.liboqs-upstream.active", "false"])
    git!(ctx.consumer, ["config", "submodule.liboqs-upstream.update", "none"])
    git!(ctx.consumer, ["config", "submodule.active", "!nifs/**"])
    assert Source.prepare!(ctx.package) == :ok
    assert git!(ctx.vendor, ["rev-parse", "HEAD"]) == ctx.a
  end

  for update <- ["none", "merge", "rebase", "custom"] do
    test "explicit checkout defeats local update=#{update} at a clean wrong revision", ctx do
      assert Source.prepare!(ctx.package) == :ok
      git!(ctx.vendor, ["checkout", "--detach", ctx.b])
      marker = Path.join(ctx.tmp, "custom-update-was-run")
      update = unquote(update)
      strategy = if update == "custom", do: "!touch " <> shell_quote(marker), else: update
      git!(ctx.consumer, ["config", "submodule.liboqs-upstream.update", strategy])
      git!(ctx.consumer, ["config", "submodule.liboqs-upstream.active", "false"])
      git!(ctx.consumer, ["config", "submodule.liboqs-upstream.branch", "main"])
      assert Source.prepare!(ctx.package) == :ok
      assert git!(ctx.vendor, ["rev-parse", "HEAD"]) == ctx.a
      assert File.read!(Path.join(ctx.vendor, "revision.txt")) == "A\n"
      refute File.exists?(marker)
    end
  end

  test "staged gitlink differing from HEAD is rejected before changing the checkout", ctx do
    git!(ctx.consumer, ["update-index", "--cacheinfo", "160000,#{ctx.b},#{@vendor}"])
    before = repo_snapshot(ctx.consumer)
    assert_raise ArgumentError, ~r/liboqs|gitlink|source/i, fn -> Source.prepare!(ctx.package) end
    assert repo_snapshot(ctx.consumer) == before
    refute File.regular?(Path.join(ctx.vendor, "CMakeLists.txt"))
    assert git!(ctx.consumer, ["ls-files", "--stage", "--", @vendor]) =~ ctx.b
  end

  for kind <- [:tracked, :staged, :untracked] do
    test "#{kind} local vendor changes are rejected and never overwritten", ctx do
      assert Source.prepare!(ctx.package) == :ok
      git!(ctx.vendor, ["checkout", "--detach", ctx.b])
      file = dirty_vendor!(ctx, unquote(kind))
      before = git!(ctx.vendor, ["status", "--porcelain", "--untracked-files=all"])

      assert_raise ArgumentError, ~r/liboqs|source|modified/i, fn ->
        Source.prepare!(ctx.package)
      end

      assert File.read!(file) == "keep my local change\n"
      assert git!(ctx.vendor, ["rev-parse", "HEAD"]) == ctx.b
      assert git!(ctx.vendor, ["status", "--porcelain", "--untracked-files=all"]) == before
    end
  end

  test "modified gitmodules is rejected before registration or cloning", ctx do
    File.write!(Path.join(ctx.consumer, ".gitmodules"), "\n# local change\n", [:append])
    before = repo_snapshot(ctx.consumer)
    assert_raise ArgumentError, ~r/gitmodules|source/i, fn -> Source.prepare!(ctx.package) end
    assert repo_snapshot(ctx.consumer) == before
    refute File.regular?(Path.join(ctx.vendor, "CMakeLists.txt"))
  end

  test "existing vendor files without submodule metadata are not overwritten in a checkout",
       ctx do
    write_vendor!(ctx.vendor, "local")
    before = File.read!(Path.join(ctx.vendor, @sign))

    assert_raise ArgumentError, ~r/liboqs|source|overwrite/i, fn ->
      Source.prepare!(ctx.package)
    end

    assert File.read!(Path.join(ctx.vendor, @sign)) == before
    assert File.read!(Path.join(ctx.vendor, "revision.txt")) == "local\n"
    refute File.exists?(Path.join(ctx.vendor, ".git"))
  end

  test "a source archive without Git metadata accepts complete vendor", ctx do
    package = Path.join(ctx.tmp, "archive")
    write_vendor!(Path.join(package, "vendor/liboqs"), "archive")
    assert Source.prepare!(package) == :ok
    refute File.exists?(Path.join(package, ".git"))
  end

  test "a source archive missing a required source file fails clearly", ctx do
    package = Path.join(ctx.tmp, "incomplete-archive")
    vendor = Path.join(package, "vendor/liboqs")
    write_vendor!(vendor, "archive")
    File.rm!(Path.join(vendor, @sign))
    assert_raise ArgumentError, ~r/liboqs|source|sign.c/i, fn -> Source.prepare!(package) end
    refute File.exists?(Path.join(package, ".git"))
  end

  test "archives inside an unrelated consumer Git root never initialize its submodules", ctx do
    outer = Path.join(ctx.tmp, "outer-consumer")
    init_repo!(outer)
    File.write!(Path.join(outer, "sentinel.txt"), "outer repository must stay intact\n")
    commit!(outer, "unrelated app")
    package = Path.join(outer, "deps/tensorcash_nif")
    vendor = Path.join(package, "vendor/liboqs")
    write_vendor!(vendor, "archive")
    before = repo_snapshot(outer)
    assert Source.prepare!(package) == :ok
    assert repo_snapshot(outer) == before
    File.rm!(Path.join(vendor, @sign))
    before_missing = repo_snapshot(outer)
    assert_raise ArgumentError, ~r/liboqs|source/i, fn -> Source.prepare!(package) end
    assert repo_snapshot(outer) == before_missing
    refute File.exists?(Path.join(outer, ".git/modules"))
  end

  test "worktrees with a gitfile retain correct repository ownership", ctx do
    worktree = Path.join(ctx.tmp, "linked-worktree")
    git!(ctx.monorepo, ["worktree", "add", "--detach", worktree, "HEAD"])
    assert File.regular?(Path.join(worktree, ".git"))
    assert Source.prepare!(Path.join(worktree, "nifs/tensorcash")) == :ok
    assert git!(Path.join(worktree, @vendor), ["rev-parse", "HEAD"]) == ctx.a
  end

  test "update=none inherited from committed gitmodules does not skip initialization", ctx do
    git!(ctx.consumer, [
      "config",
      "--file",
      ".gitmodules",
      "submodule.liboqs-upstream.update",
      "none"
    ])

    commit!(ctx.consumer, "disable default update strategy")
    assert Source.prepare!(ctx.package) == :ok
    assert git!(ctx.vendor, ["rev-parse", "HEAD"]) == ctx.a
  end

  test "a checkout hook cannot turn modified vendor into reported successful preparation", ctx do
    assert Source.prepare!(ctx.package) == :ok
    git!(ctx.vendor, ["checkout", "--detach", ctx.b])
    hooks = Path.join(ctx.tmp, "fixture-hooks")
    File.mkdir_p!(hooks)
    hook = Path.join(hooks, "post-checkout")
    file = Path.join(ctx.vendor, @sign)
    File.write!(hook, "#!/bin/sh\nprintf 'hook mutation\\n' > " <> shell_quote(file) <> "\n")
    File.chmod!(hook, 0o755)
    git!(ctx.vendor, ["config", "core.hooksPath", hooks])

    assert_raise ArgumentError, ~r/liboqs|source|modified/i, fn ->
      Source.prepare!(ctx.package)
    end

    assert File.read!(file) == "hook mutation\n"
    assert git!(ctx.vendor, ["rev-parse", "HEAD"]) == ctx.a
  end

  test "an archive with no vendor fails without creating Git metadata", ctx do
    package = Path.join(ctx.tmp, "empty-archive")
    File.mkdir_p!(package)
    assert_raise ArgumentError, ~r/liboqs|source/i, fn -> Source.prepare!(package) end
    refute File.exists?(Path.join(package, ".git"))
    refute File.exists?(Path.join(package, "vendor/liboqs"))
  end

  test "an unrelated outer repository with a matching gitlink is not adopted as chain-nifs",
       ctx do
    outer = Path.join(ctx.tmp, "outer-with-gitlink")
    init_repo!(outer)
    package = Path.join(outer, "deps/tensorcash_nif")
    relative = "deps/tensorcash_nif/vendor/liboqs"
    vendor = Path.join(outer, relative)
    File.mkdir_p!(vendor)
    File.write!(Path.join(package, "fixture.txt"), "unpacked dependency\n")
    git!(outer, ["config", "--file", ".gitmodules", "submodule.liboqs-upstream.path", relative])

    git!(outer, [
      "config",
      "--file",
      ".gitmodules",
      "submodule.liboqs-upstream.url",
      "file://" <> URI.encode(ctx.upstream)
    ])

    git!(outer, ["update-index", "--add", "--cacheinfo", "160000,#{ctx.a},#{relative}"])
    commit!(outer, "unrelated app owns this gitlink")

    assert git!(outer, ["ls-tree", "HEAD", "--", relative]) ==
             "160000 commit #{ctx.a}\t#{relative}"

    before = repo_snapshot(outer)
    assert_raise ArgumentError, ~r/liboqs|source|repository/i, fn -> Source.prepare!(package) end
    assert repo_snapshot(outer) == before
    refute File.exists?(Path.join(vendor, ".git"))
    refute File.exists?(Path.join(outer, ".git/modules"))
  end

  test "precompiled validation failure never invokes Git even with no vendor", ctx do
    bin = Path.join(ctx.tmp, "git-sentinel-bin")
    File.mkdir_p!(bin)
    marker = Path.join(ctx.tmp, "unexpected-git-in-precompiled")
    fake_git = Path.join(bin, "git")
    File.write!(fake_git, "#!/bin/sh\nprintf called > " <> shell_quote(marker) <> "\nexit 91\n")
    File.chmod!(fake_git, 0o755)
    source = Path.expand("../lib/tensor_cash_nif/source.ex", __DIR__)
    precompiled = Path.expand("../lib/tensor_cash_nif/precompiled.ex", __DIR__)
    package = Path.join(ctx.tmp, "precompiled-without-vendor")
    File.mkdir_p!(package)

    code = """
    Code.require_file(#{inspect(source)})
    Code.require_file(#{inspect(precompiled)})
    try do
      TensorCashNif.Precompiled.rustler_options!(#{inspect(package)}, %{"CHAIN_NIFS_MODE" => "precompiled"})
      raise "unexpected success with missing precompiled artifact"
    rescue
      e in ArgumentError -> IO.puts("EXPECTED_PRECOMPILED_FAILURE:" <> Exception.message(e))
    end
    """

    code_paths =
      case :code.lib_dir(:jason) do
        path when is_list(path) -> ["-pa", Path.join(List.to_string(path), "ebin")]
        {:error, _} -> []
      end

    {output, status} =
      System.cmd(System.find_executable("elixir"), code_paths ++ ["-e", code],
        env: [{"PATH", bin <> ":" <> System.get_env("PATH", "")}],
        stderr_to_stdout: true
      )

    assert status == 0, output
    assert output =~ "EXPECTED_PRECOMPILED_FAILURE:"
    refute File.exists?(marker), output
    refute File.exists?(Path.join(package, "vendor"))
  end

  defp dirty_vendor!(ctx, kind) do
    relative = if kind == :untracked, do: "local-notes.txt", else: @sign
    file = Path.join(ctx.vendor, relative)
    File.write!(file, "keep my local change\n")
    if kind == :staged, do: git!(ctx.vendor, ["add", "--", relative])
    file
  end

  defp repo_snapshot(repo) do
    status = git!(repo, ["status", "--porcelain", "--untracked-files=all"])

    %{
      head: git!(repo, ["rev-parse", "HEAD"]),
      index: File.read!(Path.join(repo, ".git/index")),
      config: File.read!(Path.join(repo, ".git/config")),
      status: status
    }
  end

  defp shell_quote(text), do: "'" <> String.replace(text, "'", "'\\''") <> "'"

  defp init_repo!(path) do
    File.mkdir_p!(path)
    git!(path, ["init", "--initial-branch=main"])
    git!(path, ["config", "user.name", "Source Fixture"])
    git!(path, ["config", "user.email", "source-fixture@example.invalid"])
    git!(path, ["config", "core.hooksPath", "/dev/null"])
  end

  defp write_vendor!(path, revision) do
    File.mkdir_p!(Path.dirname(Path.join(path, @sign)))
    File.write!(Path.join(path, "CMakeLists.txt"), "# complete fixture source\n")
    File.write!(Path.join(path, @sign), "/* fixture sign implementation */\n")
    File.write!(Path.join(path, "revision.txt"), revision <> "\n")
  end

  defp commit!(repo, message) do
    git!(repo, ["add", "--all"])

    git!(repo, [
      "-c",
      "user.name=Source Fixture",
      "-c",
      "user.email=source-fixture@example.invalid",
      "-c",
      "core.hooksPath=/dev/null",
      "commit",
      "--no-gpg-sign",
      "-m",
      message
    ])
  end

  defp git!(repo, args) do
    {output, status} = System.cmd("git", ["-C", repo | args], stderr_to_stdout: true)
    assert status == 0, "git #{inspect(args)} failed (#{status}): #{output}"
    String.trim(output)
  end
end
