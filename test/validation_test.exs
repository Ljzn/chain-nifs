defmodule Parano1dNif.ValidationTest do
  use ExUnit.Case, async: false
  alias Parano1dNif, as: API
  alias Parano1dNif.Fixtures, as: F

  test "binary and version limits reject bad arguments before native work" do
    for secret <- [nil, [], 7, <<>>, <<0::248>>, <<0::264>>] do
      assert {:error, _} = API.derive_address(secret)
      assert {:error, _} = API.authorize_transaction(<<1>>, secret)
    end

    for raw <- [nil, [], 7, <<>>, :binary.copy(<<0>>, API.max_raw_bytes() + 1)] do
      assert {:error, _} = API.verify_transaction(raw)
      assert {:error, _} = API.authorize_transaction(raw, F.secret())
    end

    assert {:error, _} = API.authorize_transaction(:binary.copy(<<0>>, 2592), F.secret())
    assert {:error, _} = API.verify_transaction(<<1, 2, 3>>)
    assert {:error, _} = API.build_transaction(%{})
    assert {:error, _} = API.build_transaction(nil)
  end

  test "prototype list and integer bounds are enforced" do
    request = F.request(1)

    bad_requests = [
      %{request | inputs: []},
      %{request | inputs: List.duplicate(hd(request.inputs), 65)},
      %{request | inputs: [hd(request.inputs) | :improper]},
      %{request | outputs: []},
      %{request | outputs: List.duplicate(hd(request.outputs), 3)},
      %{request | epoch_anchor: <<0>>},
      %{request | owner: :binary.copy(<<1>>, 129)},
      %{request | fee: -1},
      %{request | fee: 0x10000000000000000},
      put_in(request, [:inputs, Access.at(0), :slot_index], 0x100000000),
      put_in(request, [:inputs, Access.at(0), :amount], -1),
      put_in(request, [:inputs, Access.at(0), :creation_id], 0x10000000000000000),
      put_in(request, [:outputs, Access.at(0), :slot_index], -1),
      put_in(request, [:outputs, Access.at(0), :amount], 0x10000000000000000),
      put_in(request, [:outputs, Access.at(0), :owner], [])
    ]

    for invalid <- bad_requests, do: assert({:error, _} = API.build_transaction(invalid))
    assert {:ok, maximum} = API.build_transaction(F.request(64, 2))
    assert maximum.page_count == 8
  end

  test "ordinary payment boundary rejects contract flags, duplicate slots and noncanonical addresses" do
    request = F.request(2)
    assert {:error, _} = API.build_transaction(%{request | owner: String.upcase(request.owner)})

    assert {:error, _} =
             API.build_transaction(%{request | inputs: [hd(request.inputs), hd(request.inputs)]})

    assert {:error, _} =
             API.build_transaction(put_in(request, [:outputs, Access.at(0), :slot_index], 1))

    {:ok, unsigned} = API.build_transaction(request)
    # 3-byte intent prefix + 320-byte page fields precede its validity bitmap.
    <<head::binary-size(323), bitmap::little-16, tail::binary>> = unsigned.raw_transaction

    for flag <- [0x1000, 0x2000, 0x3000] do
      changed = head <> <<Bitwise.bor(bitmap, flag)::little-16>> <> tail
      assert {:error, _} = API.authorize_transaction(changed, F.secret())
    end
  end

  test "malformed bech32 and unbalanced requests return errors" do
    request = F.request(1)
    assert {:error, _} = API.build_transaction(%{request | owner: "o1invalid"})
    assert {:error, _} = API.build_transaction(%{request | fee: 50})
  end
end
