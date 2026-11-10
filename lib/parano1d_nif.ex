defmodule Parano1dNif do
  @moduledoc """
  Standalone prototype transaction harness. Only authorization version 4 is supported.

  Requests use atom keys and contain an owner address, a 32-byte epoch anchor,
  a u64 fee, 1..64 inputs and 1..2 outputs. Input fields are slot_index (u32),
  amount (u64), and creation_id (u64); output fields are slot_index (u32),
  amount (u64), and owner (address). At most eight proof pages are supported.

  Native proof and verification calls share a single native admission gate;
  competing calls return {:error, "busy"}. Callers should retry with their own
  bounded queue policy. Secrets and transaction binaries are never logged.
  """
  alias Parano1dNif.Native

  @max_raw_bytes 264_735
  @max_unsigned_bytes 2_591
  @max_u32 0xFFFFFFFF
  @max_u64 0xFFFFFFFFFFFFFFFF

  @type result :: {:ok, map() | String.t()} | {:error, String.t()}

  @doc "Maximum transaction binary accepted before entering native code."
  def max_raw_bytes, do: @max_raw_bytes

  @doc "Whether native proof or verification work currently holds the admission gate."
  def proof_busy?, do: Native.proof_busy()

  @spec derive_address(binary()) :: result()
  def derive_address(secret32) do
    with :ok <- secret(secret32), do: invoke(fn -> Native.derive_address(secret32) end)
  end

  @spec build_transaction(map()) :: result()
  def build_transaction(request) do
    with :ok <- request(request), do: invoke(fn -> Native.build_transaction(request) end)
  end

  @spec authorize_transaction(binary(), binary(), integer()) :: result()
  def authorize_transaction(unsigned_raw_binary, secret32, version \\ 4) do
    with :ok <- version(version),
         :ok <- unsigned_raw(unsigned_raw_binary),
         :ok <- secret(secret32) do
      invoke(fn -> Native.authorize_transaction(unsigned_raw_binary, secret32, version) end)
    end
  end

  @spec verify_transaction(binary(), integer()) :: result()
  def verify_transaction(raw_binary, version \\ 4) do
    with :ok <- version(version), :ok <- raw(raw_binary) do
      invoke(fn -> Native.verify_transaction(raw_binary, version) end)
    end
  end

  defp invoke(fun) do
    fun.()
  rescue
    ArgumentError -> {:error, "invalid native argument"}
  end

  defp version(4), do: :ok
  defp version(_), do: {:error, "only authorization version 4 is supported"}
  defp secret(value) when is_binary(value) and byte_size(value) == 32, do: :ok
  defp secret(_), do: {:error, "secret must be exactly 32 bytes"}

  defp raw(value)
       when is_binary(value) and byte_size(value) > 0 and byte_size(value) <= @max_raw_bytes,
       do: :ok

  defp raw(_), do: {:error, "transaction must be a nonempty binary of at most 264735 bytes"}

  defp unsigned_raw(value) when is_binary(value) and byte_size(value) <= @max_unsigned_bytes,
    do: raw(value)

  defp unsigned_raw(_), do: {:error, "unsigned transaction exceeds 2591 bytes"}

  defp address(value)
       when is_binary(value) and byte_size(value) >= 3 and byte_size(value) <= 128,
       do: :ok

  defp address(_), do: {:error, "address must be a binary of 3..128 bytes"}
  defp uint(value, max) when is_integer(value) and value >= 0 and value <= max, do: :ok
  defp uint(_, _), do: {:error, "integer outside unsigned field range"}

  defp request(%{owner: owner, epoch_anchor: anchor, fee: fee, inputs: inputs, outputs: outputs}) do
    with :ok <- address(owner),
         :ok <- anchor(anchor),
         :ok <- uint(fee, @max_u64),
         :ok <- entries(inputs, 64, &input/1),
         :ok <- entries(outputs, 2, &output/1),
         do: :ok
  end

  defp request(_),
    do: {:error, "request must contain owner, epoch_anchor, fee, inputs and outputs"}

  defp anchor(value) when is_binary(value) and byte_size(value) == 32, do: :ok
  defp anchor(_), do: {:error, "epoch_anchor must be exactly 32 bytes"}
  defp entries([], _, _), do: {:error, "input and output lists must be nonempty"}
  defp entries(values, max, validator), do: entries_nonempty(values, max, validator)
  defp entries_nonempty([], _, _), do: :ok

  defp entries_nonempty([value | rest], remaining, validator) when remaining > 0 do
    with :ok <- validator.(value), do: entries_nonempty(rest, remaining - 1, validator)
  end

  defp entries_nonempty(_, _, _), do: {:error, "invalid list or prototype item limit exceeded"}

  defp input(%{slot_index: slot, amount: amount, creation_id: creation}) do
    with :ok <- uint(slot, @max_u32),
         :ok <- uint(amount, @max_u64),
         :ok <- uint(creation, @max_u64),
         do: :ok
  end

  defp input(_), do: {:error, "input requires slot_index, amount and creation_id"}

  defp output(%{slot_index: slot, amount: amount, owner: owner}) do
    with :ok <- uint(slot, @max_u32),
         :ok <- uint(amount, @max_u64),
         :ok <- address(owner),
         do: :ok
  end

  defp output(_), do: {:error, "output requires slot_index, amount and owner"}
end
