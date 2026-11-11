defmodule TensorCashNif.ReviewRegressionTest do
  use ExUnit.Case, async: false
  import TensorCashNif.TestOracle
  alias TensorCashNif, as: Nif
  alias TensorCashNif.Native
  @max_money 2_100_000_000_000_000

  setup_all do
    oracle = fixture()
    {:ok, p: payment(oracle, hd(oracle["transactions"]))}
  end

  for n <- [1, 64] do
    test "#{n} inputs and 16 outputs have exact signed serialization metrics", %{p: p} do
      n = unquote(n)
      inputs = inputs(p, n)
      outputs = List.duplicate(%{hd(p.outputs) | amount: 1}, 16)
      base = 698 + 41 * n
      weight = base * 4 + 2 + 5326 * n

      for module <- [Nif, Native] do
        assert {:ok, unsigned} = module.unsigned_payment(p.pk, p.network, inputs, outputs)
        assert byte_size(hex(unsigned.raw_hex)) == base
        assert {:ok, signed} = module.build_payment(p.seed, p.network, inputs, outputs)
        assert signed.digests == unsigned.digests
        raw = hex(signed.raw_hex)
        assert byte_size(raw) == 700 + 5367 * n
        assert byte_size(raw) == if(n == 1, do: 6067, else: 344_188)
        assert signed.weight == weight
        assert signed.vsize == div(weight + 3, 4)
        assert module.verify_payment(raw, p.pk, p.network, inputs) == {:ok, true}
      end
    end
  end

  test "MAX_MONEY is inclusive and positive outputs permit zero fee", %{p: p} do
    inputs = [%{hd(p.inputs) | amount: @max_money}]
    outputs = [%{hd(p.outputs) | amount: @max_money}]

    for module <- [Nif, Native] do
      assert {:ok, unsigned} = module.unsigned_payment(p.pk, p.network, inputs, outputs)
      assert unsigned.fee == 0
      assert {:ok, signed} = module.build_payment(p.seed, p.network, inputs, outputs)
      assert signed.fee == 0
      assert module.verify_payment(hex(signed.raw_hex), p.pk, p.network, inputs) == {:ok, true}
    end
  end

  test "zero, above MAX_MONEY and aggregate money overflow are rejected", %{p: p} do
    [one, two] = inputs(p, 2)
    output = hd(p.outputs)

    for module <- [Nif, Native] do
      for amounts <- [[0], [@max_money + 1], [@max_money, 1]] do
        bad = Enum.zip_with([one, two], amounts, &%{&1 | amount: &2})
        assert {:error, _} = module.unsigned_payment(p.pk, p.network, bad, [output])
        assert {:error, _} = module.build_payment(p.seed, p.network, bad, [output])
        assert {:error, _} = module.verify_payment(p.raw, p.pk, p.network, bad)
      end

      for amounts <- [[0], [@max_money + 1], [@max_money, 1]] do
        bad = Enum.map(amounts, &%{output | amount: &1})
        good = [%{one | amount: @max_money}]
        assert {:error, _} = module.unsigned_payment(p.pk, p.network, good, bad)
        assert {:error, _} = module.build_payment(p.seed, p.network, good, bad)
      end
    end
  end

  test "coinbase prevouts cannot be built or verified", %{p: p} do
    bad = [%{hd(p.inputs) | txid: String.duplicate("00", 32), vout: 0xFFFFFFFF}]

    for module <- [Nif, Native] do
      assert {:error, _} = module.unsigned_payment(p.pk, p.network, bad, p.outputs)
      assert {:error, _} = module.build_payment(p.seed, p.network, bad, p.outputs)
      assert {:error, _} = module.verify_payment(p.raw, p.pk, p.network, bad)
    end
  end

  test "zero, replaceable and final sequences sign distinct digests", %{p: p} do
    payments =
      for sequence <- [0, 0xFFFFFFFD, 0xFFFFFFFF] do
        inputs = [%{hd(inputs(p, 1)) | sequence: sequence}]
        outputs = [%{hd(p.outputs) | amount: 1}]
        assert {:ok, signed} = Nif.build_payment(p.seed, p.network, inputs, outputs)
        raw = hex(signed.raw_hex)
        assert binary_part(raw, 44, 4) == <<sequence::little-unsigned-32>>
        assert Nif.verify_payment(raw, p.pk, p.network, inputs) == {:ok, true}
        changed = [%{hd(inputs) | sequence: Bitwise.bxor(sequence, 1)}]
        assert Nif.verify_payment(raw, p.pk, p.network, changed) == {:ok, false}
        signed
      end

    assert length(Enum.uniq_by(payments, & &1.digests)) == 3
    assert length(Enum.uniq_by(payments, & &1.txid)) == 3
  end

  test "raw cap is inclusive and oversized data is rejected before other validation", %{p: p} do
    for {module, reason} <- [
          {Nif, "raw transaction exceeds 524288 bytes or is not binary"},
          {Native, "raw transaction exceeds prototype limit"}
        ] do
      assert module.verify_payment(zeros(524_288), p.pk, p.network, p.inputs) ==
               {:error, "only transaction version 2 is supported"}

      assert module.verify_payment(zeros(524_289), p.pk, p.network, p.inputs) ==
               {:error, reason}

      assert module.verify_payment(zeros(524_289), <<>>, "invalid", []) ==
               {:error, reason}
    end
  end

  test "Native identity derivation validates lengths and rejects undecodable types" do
    seed = zeros(64)
    genesis = zeros(32)

    for size <- [0, 63, 65],
        do: assert({:error, _} = Native.identity_seed(zeros(size), genesis, 0))

    for size <- [0, 31, 33],
        do: assert({:error, _} = Native.identity_seed(seed, zeros(size), 0))

    for args <-
          [[nil, genesis, 0], [seed, [], 0]] ++
            Enum.map([-1, 0x100000000, "0", 0.0], &[seed, genesis, &1]) do
      assert_raise ArgumentError, fn -> apply(Native, :identity_seed, args) end
    end
  end

  test "Native spending derivation validates every binary length and branch domain" do
    seed = zeros(64)
    field = zeros(32)
    args = [seed, field, 0, field, 0, 0]

    for {position, sizes} <- [{0, [0, 63, 65]}, {1, [0, 31, 33]}, {3, [0, 31, 33]}],
        size <- sizes do
      assert {:error, _} = spending(List.replace_at(args, position, zeros(size)))
    end

    for branch <- [2, 255, 256, 257, 65_536, 0xFFFFFFFF] do
      try do
        assert {:error, _} = spending(List.replace_at(args, 4, branch))
      rescue
        ArgumentError -> :ok
      end
    end

    for {position, values} <- [
          {0, [nil]},
          {1, [[]]},
          {3, [:bad]},
          {2, [-1, 0x100000000, "0"]},
          {4, [-1, :bad, 0.0]},
          {5, [-1, 0x100000000, "0"]}
        ],
        value <- values do
      assert_raise ArgumentError, fn -> spending(List.replace_at(args, position, value)) end
    end
  end

  test "Native address derivation rejects malformed lengths, networks and types", %{p: p} do
    for size <- [0, 1951, 1953] do
      assert {:error, _} = Native.derive_address(zeros(size), p.network)
    end

    for network <- ["", "unknown", "MAINNET", :binary.copy(<<255>>, 7)] do
      assert {:error, _} = Native.derive_address(p.pk, network)
    end

    for pk <- [nil, []] do
      assert_raise ArgumentError, fn -> Native.derive_address(pk, p.network) end
    end

    for network <- [:regtest, nil, 1] do
      assert_raise ArgumentError, fn -> Native.derive_address(p.pk, network) end
    end
  end

  test "wrapper rejects improper lists and empty or excess counts", %{p: p} do
    for bad <- [[], inputs(p, 65), [hd(p.inputs) | :bad_tail]] do
      assert {:error, _} = Nif.unsigned_payment(p.pk, p.network, bad, p.outputs)
      assert {:error, _} = Nif.build_payment(p.seed, p.network, bad, p.outputs)
      assert {:error, _} = Nif.verify_payment(p.raw, p.pk, p.network, bad)
    end

    for bad <- [[], List.duplicate(hd(p.outputs), 17), [hd(p.outputs) | :bad_tail]] do
      assert {:error, _} = Nif.unsigned_payment(p.pk, p.network, p.inputs, bad)
      assert {:error, _} = Nif.build_payment(p.seed, p.network, p.inputs, bad)
    end
  end

  defp spending(args), do: apply(Native, :spending_seed, args)
  defp zeros(size), do: :binary.copy(<<0>>, size)

  defp inputs(p, count) do
    for vout <- 0..(count - 1), do: %{hd(p.inputs) | vout: vout, amount: 1000}
  end
end
