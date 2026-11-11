defmodule TensorCashNif.NativeBoundaryTest do
  use ExUnit.Case, async: false
  import TensorCashNif.TestOracle
  alias TensorCashNif, as: Nif
  alias TensorCashNif.Native

  setup_all do
    oracle = fixture()
    {:ok, p: payment(oracle, hd(oracle["transactions"]))}
  end

  test "published count and raw size limits are enforced at both boundaries", %{p: p} do
    assert Nif.limits() == %{max_inputs: 64, max_outputs: 16, max_raw_bytes: 524_288}

    for module <- [Nif, Native] do
      for inputs <- [[], List.duplicate(hd(p.inputs), 65)] do
        assert {:error, _} = module.unsigned_payment(p.pk, p.network, inputs, p.outputs)
        assert {:error, _} = module.build_payment(p.seed, p.network, inputs, p.outputs)
        assert {:error, _} = module.verify_payment(p.raw, p.pk, p.network, inputs)
      end

      for outputs <- [[], List.duplicate(hd(p.outputs), 17)] do
        assert {:error, _} = module.unsigned_payment(p.pk, p.network, p.inputs, outputs)
        assert {:error, _} = module.build_payment(p.seed, p.network, p.inputs, outputs)
      end

      assert {:error, _} =
               module.verify_payment(:binary.copy(<<0>>, 524_289), p.pk, p.network, p.inputs)
    end
  end

  test "direct native input decoding rejects malformed maps, improper lists and huge fields", %{
    p: p
  } do
    input = hd(p.inputs)

    malformed = [
      nil,
      %{},
      [nil],
      [%{}],
      [input | :bad_tail],
      [Map.delete(input, :amount)],
      [%{"txid" => input.txid}],
      [%{input | txid: :binary.copy("a", 100_000)}],
      [%{input | txid: String.duplicate("z", 64)}],
      [%{input | txid: :binary.copy(<<255>>, 64)}],
      [%{input | vout: -1}],
      [%{input | vout: 0x100000000}],
      [%{input | sequence: 0x100000000}],
      [%{input | amount: -1}],
      [%{input | amount: 18_446_744_073_709_551_616}]
    ]

    for inputs <- malformed do
      assert {:error, _} = Native.unsigned_payment(p.pk, p.network, inputs, p.outputs)
      assert {:error, _} = Native.build_payment(p.seed, p.network, inputs, p.outputs)
      assert {:error, _} = Native.verify_payment(p.raw, p.pk, p.network, inputs)
    end
  end

  test "direct native output decoding rejects malformed maps, improper lists and huge fields", %{
    p: p
  } do
    output = hd(p.outputs)

    for outputs <- [
          nil,
          %{},
          [nil],
          [%{}],
          [output | :bad_tail],
          [Map.delete(output, :address)],
          [%{output | address: nil}],
          [%{output | address: :binary.copy("a", 100_000)}],
          [%{output | amount: -1}],
          [%{output | amount: 0}],
          [%{output | amount: 18_446_744_073_709_551_616}]
        ] do
      assert {:error, _} = Native.unsigned_payment(p.pk, p.network, p.inputs, outputs)
      assert {:error, _} = Native.build_payment(p.seed, p.network, p.inputs, outputs)
    end
  end

  test "duplicate prevouts, overspending and out-of-range money are rejected", %{p: p} do
    input = hd(p.inputs)

    for inputs <- [
          [input, input],
          [%{input | amount: 0}],
          [%{input | amount: 2_100_000_000_000_001}]
        ] do
      assert {:error, _} = Nif.unsigned_payment(p.pk, p.network, inputs, p.outputs)
    end

    outputs = [%{hd(p.outputs) | amount: Enum.sum(Enum.map(p.inputs, & &1.amount)) + 1}]
    assert {:error, _} = Nif.unsigned_payment(p.pk, p.network, p.inputs, outputs)
    assert {:error, _} = Nif.build_payment(p.seed, p.network, p.inputs, outputs)
  end

  test "direct native network binaries are bounded and validated", %{p: p} do
    for network <- [
          "",
          "mainne",
          "mainnet!",
          "unknown",
          <<255, 255, 255, 255, 255, 255, 255>>,
          :binary.copy("a", 100_000)
        ] do
      assert {:error, _} = Native.derive_address(p.pk, network)
      assert {:error, _} = Native.unsigned_payment(p.pk, network, p.inputs, p.outputs)
      assert {:error, _} = Native.verify_payment(p.raw, p.pk, network, p.inputs)
    end

    assert {:ok, _} = Native.derive_address(p.pk, "mainnet")
  end
end
