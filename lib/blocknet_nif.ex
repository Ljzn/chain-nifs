defmodule BlocknetNif do
  @moduledoc "Experimental indexed-output Blocknet RingCT wallet cryptography. No chain I/O."
  alias BlocknetNif.Native

  def seeded_secret(seed),
    do: checked(fn -> with :ok <- size(seed, 32), do: Native.seeded_secret(seed) end)

  def public_key(secret),
    do: checked(fn -> with :ok <- size(secret, 32), do: Native.public_key(secret) end)

  def derive_keys(seed),
    do: checked(fn -> with :ok <- size(seed, 64), do: Native.derive_keys(seed) end)

  def key_image(secret),
    do: checked(fn -> with :ok <- size(secret, 32), do: Native.key_image(secret) end)

  def commitment(amount, blind),
    do:
      checked(fn ->
        with :ok <- uint(amount), :ok <- size(blind, 32), do: Native.commitment(amount, blind)
      end)

  def range_prove(amount, blind),
    do:
      checked(fn ->
        with :ok <- uint(amount), :ok <- size(blind, 32), do: Native.range_prove(amount, blind)
      end)

  def range_verify(commitment, proof) do
    checked(fn ->
      with :ok <- size(commitment, 32),
           :ok <- bounded_binary(proof, 1024),
           do: Native.range_verify(commitment, proof)
    end)
  end

  def ring_sign(keys, commits, index, secret, blind, pseudo, pseudo_blind, message) do
    checked(fn ->
      with :ok <- entries(keys, 16),
           :ok <- entries(commits, 16),
           :ok <- index(index),
           :ok <- size(secret, 32),
           :ok <- size(blind, 32),
           :ok <- size(pseudo, 32),
           :ok <- size(pseudo_blind, 32),
           :ok <- size(message, 32),
           do:
             Native.ring_sign(keys, commits, index, secret, blind, pseudo, pseudo_blind, message)
    end)
  end

  def ring_verify(keys, commits, message, signature) do
    checked(fn ->
      with :ok <- entries(keys, 16),
           :ok <- entries(commits, 16),
           :ok <- size(message, 32),
           :ok <- size(signature, 1120),
           do: Native.ring_verify(keys, commits, message, signature)
    end)
  end

  def build_payment(view_secret, network, inputs, outputs, fee) do
    checked(fn ->
      with :ok <- size(view_secret, 32),
           {:ok, net} <- network(network),
           :ok <- entries(inputs, 16),
           :ok <- entries(outputs, 16),
           :ok <- uint(fee),
           do: Native.build_payment(view_secret, net, inputs, outputs, fee)
    end)
  end

  def verify_payment(raw),
    do:
      checked(fn -> with :ok <- bounded_binary(raw, 131_072), do: Native.verify_payment(raw) end)

  def receive_payment(raw, spend_secret, view_secret, network) do
    checked(fn ->
      with :ok <- bounded_binary(raw, 131_072),
           :ok <- size(spend_secret, 32),
           :ok <- size(view_secret, 32),
           {:ok, net} <- network(network),
           do: Native.receive_payment(raw, spend_secret, view_secret, net)
    end)
  end

  defp checked(fun) do
    fun.()
  rescue
    ArgumentError -> {:error, "invalid native argument"}
  end

  defp size(b, n) when is_binary(b) and byte_size(b) == n, do: :ok
  defp size(_, _), do: {:error, "invalid binary length"}
  defp bounded_binary(b, max) when is_binary(b) and byte_size(b) <= max, do: :ok
  defp bounded_binary(_, _), do: {:error, "binary exceeds prototype limit"}
  defp uint(v) when is_integer(v) and v >= 0 and v <= 0xFFFFFFFFFFFFFFFF, do: :ok
  defp uint(_), do: {:error, "expected u64"}
  defp index(v) when is_integer(v) and v >= 0 and v < 16, do: :ok
  defp index(_), do: {:error, "ring index must be 0..15"}
  defp network(:mainnet), do: {:ok, "mainnet"}
  defp network(:testnet), do: {:ok, "testnet"}
  defp network("mainnet"), do: {:ok, "mainnet"}
  defp network("testnet"), do: {:ok, "testnet"}
  defp network(_), do: {:error, "network must be mainnet or testnet"}
  defp entries([], _), do: {:error, "entries cannot be empty"}
  defp entries([_ | tail], max), do: bounded_tail(tail, max - 1)
  defp entries(_, _), do: {:error, "expected proper list"}
  defp bounded_tail([], _), do: :ok
  defp bounded_tail([_ | _], 0), do: {:error, "entry count exceeds prototype limit"}
  defp bounded_tail([_ | tail], n), do: bounded_tail(tail, n - 1)
  defp bounded_tail(_, _), do: {:error, "expected proper list"}
end
