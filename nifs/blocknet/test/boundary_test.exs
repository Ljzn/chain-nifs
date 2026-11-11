defmodule BlocknetNif.BoundaryTest do
  use ExUnit.Case, async: false
  alias BlocknetNif, as: N
  alias BlocknetNif.Native
  alias BlocknetNif.Synthetic, as: S

  setup_all do
    %{ring: S.ring("boundary"), payment: S.payment(1, 2, "boundary")}
  end

  test "wrapper rejects malformed arguments as error tuples", c do
    for value <- [nil, 12, [], <<>>, <<0::248>>, <<0::264>>, :binary.copy(<<0>>, 100_000)] do
      assert {:error, _} = N.seeded_secret(value)
      assert {:error, _} = N.public_key(value)
      assert {:error, _} = N.key_image(value)
      assert {:error, _} = N.derive_keys(value)
    end

    for amount <- [-1, 1.0, :bad, 0x10000000000000000] do
      assert {:error, _} = N.commitment(amount, c.ring.blind)
      assert {:error, _} = N.range_prove(amount, c.ring.blind)
    end

    for index <- [-1, 16, 256, 0xFFFFFFFF],
        do:
          assert(
            match?({:error, _}, S.sign(%{c.ring | input: %{c.ring.input | real_index: index}}))
          )

    assert {:error, _} = N.verify_payment(:binary.copy(<<0>>, 131_073))

    assert {:error, _} =
             N.build_payment(c.ring.secret, :unknown, c.payment.inputs, c.payment.outputs, 1)
  end

  test "direct native entry validates malformed types lengths points scalars and indices", c do
    r = c.ring

    for value <- [nil, 12, [], <<>>, <<0::248>>, <<0::264>>] do
      assert_native_rejected(fn -> Native.seeded_secret(value) end)
      assert_native_rejected(fn -> Native.derive_keys(value) end)
      assert_native_rejected(fn -> Native.public_key(value) end)
    end

    for scalar <- [<<0::256>>, :binary.copy(<<255>>, 32)] do
      assert_native_rejected(fn -> Native.public_key(scalar) end)
      assert_native_rejected(fn -> Native.key_image(scalar) end)
    end

    for index <- [-1, 16, 256, 0xFFFFFFFF, 0x100000000],
        do: assert_native_rejected(fn -> S.sign(put_in(r.input.real_index, index), Native) end)

    for keys <- [
          [],
          nil,
          ["x"],
          [S.hex(<<0::256>>) | tl(r.input.ring_keys)],
          [S.hex(:binary.copy(<<255>>, 32)) | tl(r.input.ring_keys)]
        ] do
      assert_native_rejected(fn ->
        Native.ring_verify(keys, r.input.ring_commitments, r.message, <<0::8960>>)
      end)
    end

    assert_native_rejected(fn -> Native.range_verify(:binary.copy(<<255>>, 32), <<0::64>>) end)
    assert_native_rejected(fn -> Native.commitment(-1, r.blind) end)
    assert_native_rejected(fn -> Native.commitment(0x10000000000000000, r.blind) end)
    assert_native_rejected(fn -> Native.verify_payment(:binary.copy(<<0>>, 131_073)) end)
  end

  test "direct native decoder rejects missing oversized and improper map fields", c do
    p = c.payment
    [input] = p.inputs
    [output | _] = p.outputs
    view = S.unhex(p.sender.view_secret_hex)

    bad_inputs = [
      %{},
      Map.delete(input, :secret_hex),
      Map.put(input, :secret_hex, :binary.copy("f", 100_000)),
      Map.put(input, :real_index, 256),
      Map.put(input, :real_index, 0xFFFFFFFF),
      Map.put(input, :ring_keys, [hd(input.ring_keys) | :improper]),
      Map.put(input, :ring_commitments, List.duplicate(hd(input.ring_commitments), 100_000)),
      Map.put(input, :amount, -1),
      Map.put(input, :amount, 0x10000000000000000)
    ]

    for bad <- bad_inputs do
      assert_native_rejected(fn -> Native.build_payment(view, "mainnet", [bad], p.outputs, 1) end)
    end

    for bad <- [
          %{},
          Map.put(output, :memo_hex, :binary.copy("a", 250)),
          Map.put(output, :spend_public_hex, String.duplicate("ff", 32)),
          Map.put(output, :memo_hex, "zz")
        ] do
      assert_native_rejected(fn -> Native.build_payment(view, "mainnet", p.inputs, [bad], 1) end)
    end

    for inputs <- [[input | :improper], List.duplicate(input, 100_000)] do
      assert_native_rejected(fn ->
        Native.build_payment(view, "mainnet", inputs, p.outputs, 1)
      end)
    end
  end

  test "oversized wrapper lists cost bounded reductions and improper tails reject", c do
    # Construct outside measurement; a million-cell length traversal exceeds this budget.
    short = List.duplicate(hd(c.ring.input.ring_keys), 17)
    long = List.duplicate(hd(short), 1_000_000)

    call = fn keys ->
      N.ring_verify(keys, c.ring.input.ring_commitments, c.ring.message, <<0::8960>>)
    end

    assert {:error, _} = call.(short)
    assert {:error, _} = call.(long)
    small = reductions(fn -> call.(short) end)
    large = reductions(fn -> call.(long) end)
    assert large <= small + 2_000

    for module <- [N, Native] do
      assert_native_rejected(fn ->
        module.ring_verify(
          [hd(short) | :bad],
          c.ring.input.ring_commitments,
          c.ring.message,
          <<0::8960>>
        )
      end)
    end

    # The malformed 18th cell is deliberately unreachable: only the first 16
    # entries and the next cons cell may be inspected by the bounded decoder.
    poison = Enum.reduce(1..17, :poison_tail, fn _, tail -> [hd(short) | tail] end)

    for keys <- [short, long, poison] do
      assert {:error, reason} =
               Native.ring_verify(
                 keys,
                 c.ring.input.ring_commitments,
                 c.ring.message,
                 <<0::8960>>
               )

      assert reason =~ "entry count"
    end
  end

  defp reductions(fun) do
    {:reductions, before} = Process.info(self(), :reductions)
    fun.()
    {:reductions, after_count} = Process.info(self(), :reductions)
    after_count - before
  end

  defp assert_native_rejected(fun) do
    result =
      try do
        fun.()
      rescue
        ArgumentError -> {:error, :badarg}
      end

    assert match?({:error, _}, result)
  end
end
