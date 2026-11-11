defmodule TensorCashNif.WrapperLimitTest do
  use ExUnit.Case, async: false

  test "oversized wrapper lists consume bounded reductions before rejecting" do
    {:ok, pk} = TensorCashNif.public_key(:binary.copy(<<0>>, 32))
    # Construct outside the measurement; rejection must inspect at most 65 cells.
    huge = List.duplicate(:unused, 1_000_000)
    {:reductions, before} = Process.info(self(), :reductions)
    assert {:error, _} = TensorCashNif.unsigned_payment(pk, :regtest, huge, [])
    {:reductions, after_count} = Process.info(self(), :reductions)
    assert after_count - before < 5_000
  end
end
