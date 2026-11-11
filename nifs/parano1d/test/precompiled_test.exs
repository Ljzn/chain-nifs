defmodule Parano1dNif.PrecompiledTest do
  use ExUnit.Case, async: true
  alias Parano1dNif.Precompiled

  @target "x86_64-unknown-linux-musl"
  @other "aarch64-unknown-linux-musl"

  setup do
    root =
      Path.join(System.tmp_dir!(), "parano1d_nif-artifact-#{System.unique_integer([:positive])}")

    base = Path.join([root, "priv", "precompiled", @target])
    File.mkdir_p!(base)
    on_exit(fn -> File.rm_rf!(root) end)
    bytes = "fixture bytes; validation does not dlopen"
    artifact = Path.join(base, "parano1d_nif.so")
    manifest_path = Path.join(base, "manifest.json")
    File.write!(artifact, bytes)

    manifest = %{
      "schema_version" => 1,
      "project" => "parano1d_nif",
      "target" => @target,
      "otp_major" => 27,
      "sha256" => :crypto.hash(:sha256, bytes) |> Base.encode16(case: :lower)
    }

    File.write!(manifest_path, Jason.encode!(manifest))
    %{root: root, artifact: artifact, manifest: manifest, manifest_path: manifest_path}
  end

  test "source is the default and invalid modes fail explicitly" do
    assert Precompiled.rustler_options!("/unused", %{}) == []
    assert Precompiled.rustler_options!("/unused", %{"CHAIN_NIFS_MODE" => "source"}) == []

    assert_raise ArgumentError, ~r/invalid CHAIN_NIFS_MODE/, fn ->
      Precompiled.rustler_options!("/unused", %{"CHAIN_NIFS_MODE" => "typo"})
    end
  end

  test "omitting target selects the host while explicit target is preserved for validation" do
    assert Precompiled.selected_target(%{}, @target) == @target
    assert Precompiled.selected_target(%{"CHAIN_NIFS_TARGET" => @other}, @target) == @other
    assert Precompiled.selected_target(%{"CHAIN_NIFS_TARGET" => "typo"}, @target) == "typo"
  end

  test "matching artifact and manifest register both external resources", ctx do
    assert Precompiled.verify!(ctx.root, @target, @target, "27") ==
             [ctx.manifest_path, ctx.artifact]
  end

  test "a modified binary fails SHA-256 validation", ctx do
    File.write!(ctx.artifact, "tampered")

    assert_raise ArgumentError, ~r/SHA-256 mismatch/, fn ->
      Precompiled.verify!(ctx.root, @target, @target, "27")
    end
  end

  test "wrong host, unsupported target and wrong OTP fail before reading files", ctx do
    assert_raise ArgumentError, ~r/does not match host/, fn ->
      Precompiled.verify!(ctx.root, @target, @other, "27")
    end

    for target <- [nil, "x86_64-unknown-linux-gnu", "../../escape"] do
      assert_raise ArgumentError, ~r/unsupported CHAIN_NIFS_TARGET/, fn ->
        Precompiled.verify!(ctx.root, target, @target, "27")
      end
    end

    assert_raise ArgumentError, ~r/require OTP 27/, fn ->
      Precompiled.verify!(ctx.root, @target, @target, "28")
    end
  end

  test "wrong manifest identity and ABI are rejected", ctx do
    for {key, value} <- [
          {"project", "another_app"},
          {"target", @other},
          {"otp_major", 26},
          {"schema_version", 2}
        ] do
      File.write!(ctx.manifest_path, Jason.encode!(Map.put(ctx.manifest, key, value)))

      assert_raise ArgumentError, ~r/manifest #{key} must be/, fn ->
        Precompiled.verify!(ctx.root, @target, @target, "27")
      end
    end
  end

  test "missing artifact never falls back to source", ctx do
    File.rm!(ctx.artifact)

    assert_raise ArgumentError, ~r/cannot read .*no source fallback or download/, fn ->
      Precompiled.verify!(ctx.root, @target, @target, "27")
    end
  end

  test "host detection rejects glibc and Darwin and distinguishes musl architectures" do
    assert Precompiled.detect_target!("x86_64-pc-linux-musl", {:unix, :linux}, "") == @target

    assert Precompiled.detect_target!("aarch64-unknown-linux-gnu", {:unix, :linux}, "musl libc") ==
             @other

    for {architecture, os, ldd} <- [
          {"x86_64-pc-linux-gnu", {:unix, :linux}, "GNU libc"},
          {"aarch64-apple-darwin", {:unix, :darwin}, ""}
        ] do
      assert_raise ArgumentError, ~r/requires Linux musl/, fn ->
        Precompiled.detect_target!(architecture, os, ldd)
      end
    end
  end
end
