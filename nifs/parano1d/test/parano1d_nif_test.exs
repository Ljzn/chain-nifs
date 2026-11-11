defmodule Parano1dNifTest do
  use ExUnit.Case, async: false
  alias Parano1dNif, as: API
  alias Parano1dNif.Fixtures, as: F

  @moduletag timeout: 600_000

  setup_all do
    {:ok, one: F.proof(1), two: F.proof(2), nine: F.proof(9, 2)}
  end

  test "real one, two and nine input proofs round trip with complete artifacts", context do
    for {name, count, pages} <- [{:one, 1, 1}, {:two, 2, 1}, {:nine, 9, 2}] do
      fixture = context[name]
      unsigned = fixture.unsigned
      signed = fixture.signed
      assert unsigned.authorization_version == 0
      assert unsigned.authorization_bytes == 0
      assert signed.authorization_version == 4
      assert signed.authorization_bytes > 0
      assert signed.page_count == pages
      assert length(signed.inputs) == count
      assert signed.inputs == fixture.request.inputs
      assert signed.outputs == fixture.request.outputs
      assert signed.owner == fixture.request.owner
      assert signed.epoch_anchor == fixture.request.epoch_anchor
      assert signed.fee == fixture.request.fee
      assert signed.txid == unsigned.txid
      assert signed.txid =~ ~r/\A[0-9a-f]{64}\z/
      assert {:ok, verified} = API.verify_transaction(signed.raw_transaction)
      assert verified == signed
    end
  end

  test "wrong key and unsupported versions return string errors", %{one: f} do
    assert_error(API.authorize_transaction(f.unsigned.raw_transaction, F.wrong_secret()))

    for version <- [0, 1, 2, 3, 5, -1, 256, :four] do
      assert_error(API.authorize_transaction(f.unsigned.raw_transaction, F.secret(), version))
      assert_error(API.verify_transaction(f.signed.raw_transaction, version))
    end

    assert_error(API.verify_transaction(f.unsigned.raw_transaction))
  end

  test "original proof rejects altered input, output, fee, anchor and owner", %{two: f} do
    {:ok, other_owner} = API.derive_address(F.wrong_secret())
    request = f.request

    mutations = [
      put_in(request, [:inputs, Access.at(0), :creation_id], 999),
      put_in(request, [:inputs, Access.at(0), :slot_index], 20),
      put_in(request, [:outputs, Access.at(0), :slot_index], 200),
      put_in(request, [:outputs, Access.at(0), :owner], other_owner),
      %{request | epoch_anchor: :binary.copy(<<4>>, 32)},
      %{request | owner: other_owner},
      request |> Map.put(:fee, 2) |> put_in([:outputs, Access.at(0), :amount], 198),
      request
      |> put_in([:inputs, Access.at(0), :amount], 101)
      |> put_in([:outputs, Access.at(0), :amount], 200)
    ]

    for changed <- mutations do
      assert {:ok, unsigned} = API.build_transaction(changed)

      raw =
        F.transplant_proof(
          unsigned.raw_transaction,
          f.unsigned.raw_transaction,
          f.signed.raw_transaction
        )

      assert_error(API.verify_transaction(raw))
    end
  end

  test "corrupt, truncated and surplus proof bytes are rejected", %{one: f} do
    raw = f.signed.raw_transaction
    offset = byte_size(f.unsigned.raw_transaction)
    assert_error(API.verify_transaction(F.flip_byte(raw, offset)))
    assert_error(API.verify_transaction(F.flip_byte(raw, byte_size(raw) - 1)))
    assert_error(API.verify_transaction(binary_part(raw, 0, byte_size(raw) - 1)))
    assert_error(API.verify_transaction(raw <> <<0>>))

    # Also update the declared length so these exercise proof decoding itself.
    prefix = binary_part(raw, 0, offset - 4)
    proof = binary_part(raw, offset, byte_size(raw) - offset)

    assert_error(
      API.verify_transaction(prefix <> <<byte_size(proof) + 1::little-32>> <> proof <> <<0>>)
    )

    short = binary_part(proof, 0, byte_size(proof) - 1)
    assert_error(API.verify_transaction(prefix <> <<byte_size(short)::little-32>> <> short))
  end

  test "repeated randomized proofs retain the unsigned transaction id", %{one: f} do
    assert {:ok, again} = API.authorize_transaction(f.unsigned.raw_transaction, F.secret())
    assert again.txid == f.signed.txid
    assert again.raw_transaction != f.signed.raw_transaction
    assert {:ok, verified} = API.verify_transaction(again.raw_transaction)
    assert verified.txid == f.unsigned.txid
  end

  defp assert_error(result) do
    assert {:error, message} = result
    assert is_binary(message) and byte_size(message) > 0
  end
end
