defmodule BlocknetNif.ReviewRegressionTest do
  use ExUnit.Case, async: false
  alias BlocknetNif, as: N
  alias BlocknetNif.Synthetic, as: S

  setup_all do
    prepared = S.payment(1, 3, "review-regressions")
    {:ok, payment} = S.build(prepared)
    raw = S.unhex(payment.raw_hex)
    {:ok, received} = S.receive(raw, prepared.receiver)
    %{prepared: prepared, raw: raw, received: received, layout: S.wire_layout(raw)}
  end

  test "a signed bad amount opening cannot hide valid outputs before or after it", c do
    for bad <- 0..2 do
      wire = Enum.at(c.layout.outputs, bad)
      raw = c.raw |> S.flip(wire.offset + 64) |> S.resign_single_input(c.prepared, c.received)
      assert {:ok, true} = N.verify_payment(raw)
      assert {:ok, found} = S.receive(raw, c.prepared.receiver)
      assert found == Enum.reject(c.received, &(&1.index == bad))
    end

    raw =
      Enum.reduce(c.layout.outputs, c.raw, fn wire, raw -> S.flip(raw, wire.offset + 64) end)
      |> S.resign_single_input(c.prepared, c.received)

    assert {:ok, true} = N.verify_payment(raw)
    assert {:ok, []} = S.receive(raw, c.prepared.receiver)
    # A bad signature still rejects the whole transaction; recovery never bypasses verification.
    assert {:error, _} = S.receive(S.flip(c.raw, 49 + 64), c.prepared.receiver)
  end

  test "a signed invalid memo retains funds and other owned outputs", c do
    [wire | _] = c.layout.outputs
    # Ciphertext XOR changes decrypted version 1 to 0, guaranteeing an invalid envelope.
    raw = c.raw |> S.flip(wire.offset + 72) |> S.resign_single_input(c.prepared, c.received)
    assert {:ok, true} = N.verify_payment(raw)
    assert {:ok, [first | rest]} = S.receive(raw, c.prepared.receiver)
    [original | expected_rest] = c.received
    assert first == %{original | memo_valid: false, memo_hex: ""}
    assert rest == expected_rest
  end

  test "a protocol-valid zero output is recovered without aborting its nonzero neighbors", c do
    amounts = [0, 33, 66]

    raw =
      Enum.zip([c.layout.outputs, c.received, amounts])
      |> Enum.reduce(c.raw, fn {wire, owned, amount}, raw ->
        blind = S.unhex(owned.blinding_hex)
        {:ok, commitment} = N.commitment(amount, blind)
        {:ok, proof} = N.range_prove(amount, blind)
        assert byte_size(proof) == wire.proof_bytes
        <<encrypted::little-64>> = binary_part(raw, wire.offset + 64, 8)
        encrypted = Bitwise.bxor(Bitwise.bxor(encrypted, owned.amount), amount)

        raw
        |> S.replace(wire.offset + 32, commitment)
        |> S.replace(wire.offset + 64, <<encrypted::little-64>>)
        |> S.replace(wire.proof, proof)
      end)
      |> S.resign_single_input(c.prepared, c.received)

    assert {:ok, true} = N.verify_payment(raw)
    assert {:ok, found} = S.receive(raw, c.prepared.receiver)
    assert Enum.map(found, & &1.amount) == amounts
    assert Enum.map(found, & &1.index) == [0, 1, 2]
    assert Enum.map(found, & &1.secret_hex) == Enum.map(c.received, & &1.secret_hex)
  end

  test "builder rejects duplicate decoy keys after decoding while wire verification stays compatible",
       c do
    [input] = c.prepared.inputs
    # Real index 1 is unchanged. Duplicate decoys at 2 and 3, including mixed-case hex.
    keys = List.replace_at(input.ring_keys, 3, String.upcase(Enum.at(input.ring_keys, 2)))
    commits = List.replace_at(input.ring_commitments, 3, Enum.at(input.ring_commitments, 2))

    for ring_commitments <- [input.ring_commitments, commits] do
      p = %{c.prepared | inputs: [%{input | ring_keys: keys, ring_commitments: ring_commitments}]}
      assert {:error, "duplicate ring public key"} = S.build(p)

      assert {:error, "duplicate ring public key"} =
               N.Native.build_payment(
                 S.unhex(p.sender.view_secret_hex),
                 "mainnet",
                 p.inputs,
                 p.outputs,
                 p.fee
               )

      # Construction policy does not silently add a new consensus restriction to verification.
      raw = S.resign_single_input(c.raw, p, c.received)
      assert {:ok, true} = N.verify_payment(raw)
      assert {:ok, found} = S.receive(raw, p.receiver)
      assert found == c.received
    end
  end

  test "distinct decoy keys may share a commitment", c do
    [input] = c.prepared.inputs
    commits = List.replace_at(input.ring_commitments, 3, Enum.at(input.ring_commitments, 2))
    p = %{c.prepared | inputs: [%{input | ring_commitments: commits}]}
    assert {:ok, payment} = S.build(p)
    assert {:ok, true} = N.verify_payment(S.unhex(payment.raw_hex))
  end
end
