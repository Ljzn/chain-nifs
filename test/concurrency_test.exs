defmodule TensorCashNif.ConcurrencyTest do
  use ExUnit.Case, async: false

  test "concurrent keys and signing randomness do not contaminate other callers" do
    sign_and_verify = fn i ->
      seed = :crypto.hash(:sha256, "synthetic concurrent seed #{i}")
      message = :crypto.hash(:sha256, "synthetic message #{i}")
      {:ok, pk} = TensorCashNif.public_key(seed)
      {:ok, signature} = TensorCashNif.sign(seed, message)
      {:ok, true} = TensorCashNif.verify(pk, message, signature)
      {:ok, false} = TensorCashNif.verify(pk, :crypto.hash(:sha256, "wrong #{i}"), signature)
      {pk, signature}
    end

    pairs =
      0..31
      |> Task.async_stream(sign_and_verify, max_concurrency: 8, timeout: :infinity)
      |> Enum.map(fn {:ok, result} -> result end)

    assert length(Enum.uniq_by(pairs, &elem(&1, 0))) == 32
    assert length(Enum.uniq_by(pairs, &elem(&1, 1))) == 32
  end
end
