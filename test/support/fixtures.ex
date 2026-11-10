defmodule Parano1dNif.Fixtures do
  @moduledoc false
  alias Parano1dNif, as: API

  def secret, do: :binary.copy(<<7>>, 32)
  def wrong_secret, do: :binary.copy(<<8>>, 32)

  def request(count, output_count \\ 1) do
    {:ok, owner} = API.derive_address(secret())
    total = count * 100

    outputs =
      case output_count do
        1 ->
          [%{slot_index: 100, amount: total - 1, owner: owner}]

        2 ->
          [
            %{slot_index: 100, amount: total - 2, owner: owner},
            %{slot_index: 101, amount: 1, owner: owner}
          ]
      end

    %{
      owner: owner,
      epoch_anchor: :binary.copy(<<3>>, 32),
      fee: 1,
      inputs: for(i <- 1..count, do: %{slot_index: i, amount: 100, creation_id: i}),
      outputs: outputs
    }
  end

  def proof(count, outputs \\ 1) do
    request = request(count, outputs)
    {:ok, unsigned} = API.build_transaction(request)
    {:ok, signed} = API.authorize_transaction(unsigned.raw_transaction, secret())
    %{request: request, unsigned: unsigned, signed: signed}
  end

  # The canonical paged-spend wire format ends unsigned intents with u32(0).
  # Preserve the original authorization length and proof while replacing pages.
  def transplant_proof(changed_unsigned, original_unsigned, original_signed) do
    offset = byte_size(original_unsigned) - 4
    proof_suffix = binary_part(original_signed, offset, byte_size(original_signed) - offset)
    binary_part(changed_unsigned, 0, byte_size(changed_unsigned) - 4) <> proof_suffix
  end

  def flip_byte(binary, offset) do
    <<head::binary-size(^offset), byte, tail::binary>> = binary
    head <> <<Bitwise.bxor(byte, 1)>> <> tail
  end
end
