defmodule TensorCashNif do
  @moduledoc """
  Ordinary TSC ML-DSA-65 prototype. Seeds are FIPS 204 seed32, not secp keys.
  Signing uses fresh system randomness and self-verifies. All native work runs on dirty CPU schedulers.
  Payment inputs must all belong to this key's single-leaf 1-of-1 witness-v2 address.
  Local verification does not check UTXO availability, fees, maturity, or chain admission.
  """
  alias TensorCashNif.Native
  @max_inputs 64
  @max_outputs 16
  @max_raw 512 * 1024
  def limits, do: %{max_inputs: @max_inputs, max_outputs: @max_outputs, max_raw_bytes: @max_raw}

  def public_key(seed),
    do: checked(fn -> with :ok <- size(seed, 32), do: Native.public_key(seed) end)

  def sign(seed, digest),
    do:
      checked(fn ->
        with :ok <- size(seed, 32), :ok <- size(digest, 32), do: Native.sign(seed, digest)
      end)

  def verify(pk, digest, sig),
    do:
      checked(fn ->
        with :ok <- size(pk, 1952),
             :ok <- size(digest, 32),
             :ok <- size(sig, 3309),
             do: Native.verify(pk, digest, sig)
      end)

  def spending_seed(seed64, genesis, account, policy, branch, index) do
    checked(fn ->
      with :ok <- size(seed64, 64),
           :ok <- size(genesis, 32),
           :ok <- size(policy, 32),
           :ok <- uint(account),
           :ok <- uint(index),
           true <- branch in [0, 1] do
        Native.spending_seed(seed64, genesis, account, policy, branch, index)
      else
        false -> {:error, "branch must be 0 or 1"}
        error -> error
      end
    end)
  end

  def identity_seed(seed64, genesis, account) do
    checked(fn ->
      with :ok <- size(seed64, 64),
           :ok <- size(genesis, 32),
           :ok <- uint(account),
           do: Native.identity_seed(seed64, genesis, account)
    end)
  end

  def derive_address(pk, network \\ :mainnet) do
    checked(fn ->
      with :ok <- size(pk, 1952),
           {:ok, name} <- network(network),
           do: Native.derive_address(pk, name)
    end)
  end

  def build_payment(seed, network, inputs, outputs) do
    checked(fn ->
      with :ok <- size(seed, 32),
           {:ok, name} <- network(network),
           :ok <- entries(inputs, @max_inputs),
           :ok <- entries(outputs, @max_outputs),
           do: Native.build_payment(seed, name, inputs, outputs)
    end)
  end

  def unsigned_payment(pk, network, inputs, outputs) do
    checked(fn ->
      with :ok <- size(pk, 1952),
           {:ok, name} <- network(network),
           :ok <- entries(inputs, @max_inputs),
           :ok <- entries(outputs, @max_outputs),
           do: Native.unsigned_payment(pk, name, inputs, outputs)
    end)
  end

  def verify_payment(raw, pk, network, inputs) do
    checked(fn ->
      with :ok <- raw(raw),
           :ok <- size(pk, 1952),
           {:ok, name} <- network(network),
           :ok <- entries(inputs, @max_inputs),
           do: Native.verify_payment(raw, pk, name, inputs)
    end)
  end

  defp checked(f) do
    try do
      f.()
    rescue
      ArgumentError -> {:error, "invalid argument type or field"}
    end
  end

  defp size(b, n) when is_binary(b) and byte_size(b) == n, do: :ok
  defp size(_, n), do: {:error, "expected binary of #{n} bytes"}
  defp uint(n) when is_integer(n) and n >= 0 and n <= 0xFFFFFFFF, do: :ok
  defp uint(_), do: {:error, "expected unsigned 32-bit integer"}
  defp raw(b) when is_binary(b) and byte_size(b) <= @max_raw, do: :ok
  defp raw(_), do: {:error, "raw transaction exceeds 524288 bytes or is not binary"}

  defp entries([], _), do: {:error, "entry count outside prototype limit"}
  defp entries([_ | tail], max), do: bounded_tail(tail, max - 1)
  defp entries(_, _), do: {:error, "expected proper list"}

  defp bounded_tail([], _remaining), do: :ok
  defp bounded_tail([_ | _], 0), do: {:error, "entry count outside prototype limit"}
  defp bounded_tail([_ | tail], remaining), do: bounded_tail(tail, remaining - 1)
  defp bounded_tail(_, _), do: {:error, "expected proper list"}
  defp network(n) when n in [:mainnet, :testnet, :regtest], do: {:ok, Atom.to_string(n)}
  defp network(n) when n in ["mainnet", "testnet", "regtest"], do: {:ok, n}
  defp network(_), do: {:error, "unsupported network"}
end
