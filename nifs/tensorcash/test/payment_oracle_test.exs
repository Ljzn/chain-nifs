defmodule TensorCashNif.PaymentOracleTest do
  use ExUnit.Case, async: false
  import TensorCashNif.TestOracle
  alias TensorCashNif, as: Nif

  setup_all do
    oracle = fixture()
    {:ok, oracle: oracle}
  end

  test "unsigned payments match official bytes, txids, sighashes and fees", %{oracle: oracle} do
    for tx <- oracle["transactions"] do
      p = payment(oracle, tx)
      assert {:ok, unsigned} = Nif.unsigned_payment(p.pk, p.network, p.inputs, p.outputs)
      assert unsigned.unsigned_hex == tx["unsignedTxHex"]
      assert unsigned.raw_hex == tx["unsignedTxHex"]
      assert unsigned.txid == tx["txid"]
      assert unsigned.wtxid == tx["txid"]
      assert unsigned.digests == tx["sighashesHex"]
      assert unsigned.fee == String.to_integer(tx["feeSats"])
      assert unsigned.weight == tx["baseBytes"] * 4
      assert unsigned.vsize == tx["baseBytes"]
      assert Nif.verify_payment(hex(unsigned.raw_hex), p.pk, p.network, p.inputs) == {:ok, false}
    end
  end

  test "official signed raw payments verify with their supplied prevout amounts", %{
    oracle: oracle
  } do
    for tx <- oracle["transactions"] do
      p = payment(oracle, tx)
      assert byte_size(p.raw) == tx["totalBytes"]
      assert Nif.verify_payment(p.raw, p.pk, p.network, p.inputs) == {:ok, true}
    end
  end

  test "native signed payments preserve official transaction identity and fee metrics", %{
    oracle: oracle
  } do
    for tx <- oracle["transactions"] do
      p = payment(oracle, tx)
      assert {:ok, signed} = Nif.build_payment(p.seed, p.network, p.inputs, p.outputs)
      assert signed.unsigned_hex == tx["unsignedTxHex"]
      assert signed.txid == tx["txid"]
      assert signed.digests == tx["sighashesHex"]
      assert signed.fee == String.to_integer(tx["feeSats"])
      assert signed.weight == tx["weight"]
      assert signed.vsize == tx["vsize"]
      raw = hex(signed.raw_hex)
      assert byte_size(raw) == tx["totalBytes"]
      assert Nif.verify_payment(raw, p.pk, p.network, p.inputs) == {:ok, true}

      assert signed.wtxid ==
               raw
               |> then(&:crypto.hash(:sha256, &1))
               |> then(&:crypto.hash(:sha256, &1))
               |> :binary.bin_to_list()
               |> Enum.reverse()
               |> :erlang.list_to_binary()
               |> Base.encode16(case: :lower)
    end
  end

  test "signature and amount mutations, swapped prevouts and wrong keys fail", %{oracle: oracle} do
    tx = hd(oracle["transactions"])
    p = payment(oracle, tx)
    {offset, _} = :binary.match(p.raw, hex(hd(tx["signaturesHex"])))
    rejected(Nif.verify_payment(flip(p.raw, offset), p.pk, p.network, p.inputs))
    changed = List.update_at(p.inputs, 0, &%{&1 | amount: &1.amount + 1})
    rejected(Nif.verify_payment(p.raw, p.pk, p.network, changed))
    rejected(Nif.verify_payment(p.raw, p.pk, p.network, Enum.reverse(p.inputs)))
    other = hex(key(oracle, "zero32")["publicKeyHex"])
    rejected(Nif.verify_payment(p.raw, other, p.network, p.inputs))
    # Output amounts are signed; the first follows the signed input section.
    rejected(
      Nif.verify_payment(flip(p.raw, 8 + 41 * length(p.inputs)), p.pk, p.network, p.inputs)
    )
  end

  test "truncations, trailing data and corrupted framing or counts are rejected", %{
    oracle: oracle
  } do
    tx = hd(oracle["transactions"])
    p = payment(oracle, tx)
    {signature_offset, _} = :binary.match(p.raw, hex(hd(tx["signaturesHex"])))

    for size <- [0, 1, 4, 6, 7, 40, signature_offset, byte_size(p.raw) - 1] do
      rejected(Nif.verify_payment(binary_part(p.raw, 0, size), p.pk, p.network, p.inputs))
    end

    output_count = 7 + 41 * length(p.inputs)

    for raw <- [
          p.raw <> <<0>>,
          replace(p.raw, 5, <<3>>),
          replace(p.raw, 6, <<65>>),
          replace(p.raw, output_count, <<17>>),
          replace(p.raw, signature_offset - 2, <<255, 255>>),
          replace(p.raw, 6, <<253, 2, 0>>)
        ] do
      rejected(Nif.verify_payment(raw, p.pk, p.network, p.inputs))
    end
  end

  test "wrong-network destination addresses are rejected", %{oracle: oracle} do
    p = payment(oracle, hd(oracle["transactions"]))
    assert p.network == "mainnet"
    assert {:error, _} = Nif.unsigned_payment(p.pk, :testnet, p.inputs, p.outputs)
    assert {:error, _} = Nif.build_payment(p.seed, :testnet, p.inputs, p.outputs)
    assert {:error, _} = Nif.verify_payment(p.raw, p.pk, "unknown", p.inputs)
  end

  @tag timeout: 120_000
  test "full 64-input signed payment verifies and binds every prevout amount", %{oracle: oracle} do
    p = payment(oracle, hd(oracle["transactions"]))

    inputs =
      for index <- 0..63 do
        %{
          hd(p.inputs)
          | txid: Base.encode16(<<index::256>>, case: :lower),
            vout: index,
            amount: 100_000
        }
      end

    outputs = [%{hd(p.outputs) | amount: 6_390_000}]
    assert {:ok, signed} = Nif.build_payment(p.seed, p.network, inputs, outputs)
    assert length(signed.digests) == 64
    assert signed.fee == 10_000
    raw = hex(signed.raw_hex)
    assert byte_size(raw) < Nif.limits().max_raw_bytes
    assert Nif.verify_payment(raw, p.pk, p.network, inputs) == {:ok, true}
    changed = List.update_at(inputs, 63, &%{&1 | amount: &1.amount + 1})
    rejected(Nif.verify_payment(raw, p.pk, p.network, changed))
  end
end
