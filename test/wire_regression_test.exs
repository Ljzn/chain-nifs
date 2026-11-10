defmodule Parano1dNif.WireRegressionTest do
  use ExUnit.Case, async: false

  alias Parano1dNif, as: API
  alias Parano1dNif.Fixtures, as: F
  alias Parano1dNif.Native

  @moduletag timeout: 600_000
  @max_unsigned_bytes 2_591
  @max_raw_bytes 264_735
  @page_bytes 323
  @seed {64, 2, 8}

  setup_all do
    # Generate only one proof for this file; malformed cases fail before proof work.
    {:ok, maximum: F.proof(64, 2)}
  end

  test "64 real inputs and two outputs build, authorize and verify at the eight-page limit", %{
    maximum: f
  } do
    assert API.max_raw_bytes() == @max_raw_bytes
    assert byte_size(f.unsigned.raw_transaction) == @max_unsigned_bytes
    assert <<0xA3, 8::little-16, _::binary>> = f.unsigned.raw_transaction
    assert f.unsigned.page_count == 8
    assert f.unsigned.authorization_version == 0
    assert f.unsigned.authorization_bytes == 0

    for artifact <- [f.unsigned, f.signed] do
      assert artifact.inputs == f.request.inputs
      assert length(artifact.inputs) == 64
      assert artifact.outputs == f.request.outputs
      assert length(artifact.outputs) == 2
      assert artifact.page_count == 8
      assert artifact.owner == f.request.owner
      assert artifact.epoch_anchor == f.request.epoch_anchor
      assert artifact.fee == f.request.fee
    end

    assert f.signed.authorization_version == 4
    assert f.signed.authorization_bytes > 0
    assert f.signed.txid == f.unsigned.txid
    assert f.signed.txid =~ ~r/\A[0-9a-f]{64}\z/

    assert byte_size(f.signed.raw_transaction) ==
             @max_unsigned_bytes + f.signed.authorization_bytes

    assert byte_size(f.signed.raw_transaction) <= @max_raw_bytes
    assert {:ok, verified} = API.verify_transaction(f.signed.raw_transaction)
    assert verified == f.signed
  end

  test "zero and over-limit page headers are rejected before decoding a page" do
    # Deliberately omit pages: the prototype guard must precede upstream decoding.
    for pages <- [0, 129, 65_535] ++ Enum.to_list(9..128) do
      raw = <<0xA3, pages::little-16>>

      for reason <- assert_rejected(raw) do
        assert reason == "payment exceeds prototype page limit"
      end
    end
  end

  test "seeded truncations cover headers, every page edge and authorization length", %{maximum: f} do
    raw = f.unsigned.raw_transaction

    page_edges =
      for page <- 0..8, delta <- [-1, 0, 1], do: 3 + page * @page_bytes + delta

    cuts =
      ([
         0,
         1,
         2,
         3,
         @max_unsigned_bytes - 4,
         @max_unsigned_bytes - 3,
         @max_unsigned_bytes - 2,
         @max_unsigned_bytes - 1
       ] ++
         page_edges ++ seeded_values(48, @max_unsigned_bytes))
      |> Enum.filter(&(&1 >= 0 and &1 < byte_size(raw)))
      |> Enum.uniq()

    assert length(cuts) in 60..90

    for cut <- cuts do
      assert_rejected(binary_part(raw, 0, cut))
    end
  end

  test "seeded authorization-tail mismatches and public byte limits return string errors", %{
    maximum: f
  } do
    prefix_size = @max_unsigned_bytes - 4

    <<prefix::binary-size(^prefix_size), proof_size::little-32, proof::binary>> =
      f.signed.raw_transaction

    assert proof_size == byte_size(proof)

    # Keep valid pages while making the declared tail length disagree with its bytes.
    for declared <- [0, 1, proof_size - 1, proof_size + 1, 262_143, 262_144, 262_145, 0xFFFFFFFF],
        declared != proof_size do
      assert_rejected(prefix <> <<declared::little-32>> <> proof)
    end

    for size <- seeded_values(32, 32) do
      tail = binary_part(proof, 0, size)
      assert_rejected(prefix <> <<size + 1::little-32>> <> tail)
    end

    # An invalid marker makes the exact-limit cases cheap and unambiguously malformed.
    invalid = F.flip_byte(f.unsigned.raw_transaction, 0)

    for size <- [
          @max_unsigned_bytes - 1,
          @max_unsigned_bytes,
          @max_unsigned_bytes + 1,
          @max_raw_bytes - 1,
          @max_raw_bytes,
          @max_raw_bytes + 1
        ] do
      raw = resize(invalid, size)
      assert byte_size(raw) == size
      assert_rejected(raw)
    end
  end

  defp assert_rejected(raw) do
    for result <- [
          API.authorize_transaction(raw, F.secret()),
          API.verify_transaction(raw),
          Native.authorize_transaction(raw, F.secret(), 4),
          Native.verify_transaction(raw, 4)
        ] do
      assert {:error, reason} = result
      assert is_binary(reason)
      assert byte_size(reason) > 0
      refute reason =~ "panic"
      refute reason == "busy"
      reason
    end
  end

  defp seeded_values(count, limit) do
    {values, _state} =
      Enum.map_reduce(1..count, :rand.seed_s(:exsss, @seed), fn _, state ->
        {value, state} = :rand.uniform_s(limit, state)
        {value - 1, state}
      end)

    values
  end

  defp resize(raw, size) when size <= byte_size(raw), do: binary_part(raw, 0, size)
  defp resize(raw, size), do: raw <> :binary.copy(<<0>>, size - byte_size(raw))
end
