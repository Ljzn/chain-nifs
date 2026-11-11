defmodule BlocknetNif.PaymentTest do
  use ExUnit.Case, async: false
  alias BlocknetNif, as: N
  alias BlocknetNif.Synthetic, as: S
  @moduletag timeout: 180_000
  setup_all do
    prepared = S.payment()
    {:ok, payment} = S.build(prepared)
    %{prepared: prepared, payment: payment, raw: S.unhex(payment.raw_hex)}
  end

  test "two inputs and repeated recipient outputs recover indexed secrets and 0/124-byte memos",
       c do
    assert {:ok, true} = N.verify_payment(c.raw)
    assert c.payment.bytes == byte_size(c.raw)
    assert c.payment.fee == c.prepared.fee
    assert S.unhex(c.payment.txid) == :crypto.hash(:sha3_256, c.raw)
    assert byte_size(S.unhex(c.payment.signing_hash_hex)) == 32
    assert binary_part(c.raw, 1, 32) == S.unhex(c.payment.tx_public_hex)
    assert {:ok, received} = S.receive(c.raw, c.prepared.receiver)
    assert Enum.all?(received, & &1.memo_valid)
    assert Enum.map(received, & &1.index) == [0, 1]
    assert Enum.map(received, & &1.amount) == Enum.map(c.prepared.outputs, & &1.amount)
    assert Enum.map(received, & &1.memo_hex) == Enum.map(c.prepared.outputs, & &1.memo_hex)
    assert length(Enum.uniq_by(received, & &1.secret_hex)) == 2
    layout = S.wire_layout(c.raw)

    for {item, wire} <- Enum.zip(received, layout.outputs) do
      assert {:ok, public} = N.public_key(S.unhex(item.secret_hex))
      assert public == binary_part(c.raw, wire.offset, 32)
      assert {:ok, commitment} = N.commitment(item.amount, S.unhex(item.blinding_hex))
      assert commitment == binary_part(c.raw, wire.offset + 32, 32)
    end

    assert {:ok, []} = S.receive(c.raw, c.prepared.sender)
  end

  test "payment to recipient plus change recovers only each wallet's own output", c do
    p = %{
      c.prepared
      | outputs: [
          S.output(c.prepared.receiver, 80, "recipient"),
          S.output(c.prepared.sender, 119, "change")
        ]
    }

    assert {:ok, payment} = S.build(p, "testnet")
    raw = S.unhex(payment.raw_hex)
    assert {:ok, true} = N.verify_payment(raw)
    assert {:ok, [recipient]} = S.receive(raw, p.receiver, :testnet)
    assert {recipient.index, recipient.amount, recipient.memo_hex} == {0, 80, S.hex("recipient")}
    assert {:ok, [change]} = S.receive(raw, p.sender, "testnet")
    assert {change.index, change.amount, change.memo_hex} == {1, 119, S.hex("change")}
  end

  test "network does not alter wire verification but wrong-network memo recovery fails", c do
    assert {:ok, true} = N.verify_payment(c.raw)
    assert_wrong_network(S.receive(c.raw, c.prepared.receiver, :testnet), c.prepared.outputs)
    assert {:ok, payment} = S.build(c.prepared, :testnet)
    raw = S.unhex(payment.raw_hex)
    assert {:ok, true} = N.verify_payment(raw)
    assert {:ok, received} = S.receive(raw, c.prepared.receiver, "testnet")
    assert length(received) == 2
    assert Enum.all?(received, & &1.memo_valid)
    assert_wrong_network(S.receive(raw, c.prepared.receiver, "mainnet"), c.prepared.outputs)
  end

  test "wire mutations reject truncation, trailing garbage, proof changes and pseudo mismatch",
       c do
    layout = S.wire_layout(c.raw)
    [first, second] = layout.inputs
    [output | _] = layout.outputs

    mutations = [
      <<>>,
      binary_part(c.raw, 0, 1),
      binary_part(c.raw, 0, byte_size(c.raw) - 1),
      c.raw <> <<0>>,
      S.replace(c.raw, 0, <<2>>),
      S.flip(c.raw, 41),
      S.flip(c.raw, output.proof),
      S.replace(c.raw, output.offset + 200, <<0xFFFFFFFF::little-32>>),
      S.replace(c.raw, first + 32, binary_part(c.raw, output.offset + 32, 32)),
      S.replace(c.raw, second, binary_part(c.raw, first, 32)),
      S.replace(c.raw, 33, <<0xFFFFFFFF::little-32>>),
      S.replace(c.raw, 37, <<0xFFFFFFFF::little-32>>)
    ]

    for raw <- mutations, do: assert_rejected(N.verify_payment(raw))
    # At most 32 deterministic structural/cryptographic changes, never a fuzz-time loop.
    for n <- 0..31 do
      offset = div(n * (byte_size(c.raw) - 1), 31)
      assert_rejected(N.verify_payment(S.flip(c.raw, offset)))
    end
  end

  test "builder rejects duplicate key images, overflow and unbalanced fees", c do
    p = c.prepared
    [input | _] = p.inputs

    for bad <- [
          %{p | inputs: [input, input]},
          %{p | fee: p.fee + 1},
          %{p | inputs: [S.input("overflow-a", 0xFFFFFFFFFFFFFFFF), S.input("overflow-b", 1)]},
          %{p | outputs: [S.output(p.receiver, 0xFFFFFFFFFFFFFFFF), S.output(p.receiver, 1)]},
          %{p | outputs: [S.output(p.receiver, 0)]},
          %{p | outputs: [S.output(p.receiver, 199, :binary.copy(<<1>>, 125))]}
        ],
        do: assert(match?({:error, _}, S.build(bad)))
  end

  test "two concurrent payment builds verify and recover with bounded workers", c do
    results =
      Task.async_stream(
        1..2,
        fn _ ->
          {:ok, payment} = S.build(c.prepared)
          raw = S.unhex(payment.raw_hex)
          {:ok, true} = N.verify_payment(raw)
          {:ok, received} = S.receive(raw, c.prepared.receiver)
          Enum.map(received, & &1.amount)
        end,
        max_concurrency: 4,
        timeout: 180_000
      )
      |> Enum.to_list()

    expected = Enum.map(c.prepared.outputs, & &1.amount)
    assert results == [{:ok, expected}, {:ok, expected}]
  end

  defp assert_rejected(result), do: assert(result == {:ok, false} or match?({:error, _}, result))

  defp assert_wrong_network({:ok, received}, outputs) do
    assert Enum.map(received, & &1.amount) == Enum.map(outputs, & &1.amount)
    assert Enum.all?(received, &(not &1.memo_valid and &1.memo_hex == ""))
  end
end
