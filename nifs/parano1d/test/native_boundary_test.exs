defmodule Parano1dNif.NativeBoundaryTest do
  use ExUnit.Case, async: false
  alias Parano1dNif.Native
  alias Parano1dNif.Fixtures, as: F

  test "direct native entry checks borrowed list and binary sizes before owned decoding" do
    request = F.request(1)
    huge = :binary.copy(<<1>>, 1_000_000)

    bad_requests = [
      %{request | owner: huge},
      %{request | epoch_anchor: huge},
      %{request | inputs: List.duplicate(hd(request.inputs), 100_000)},
      %{request | outputs: List.duplicate(hd(request.outputs), 100_000)},
      %{request | inputs: [hd(request.inputs) | :improper]},
      put_in(request, [:outputs, Access.at(0), :owner], huge),
      put_in(request, [:inputs, Access.at(0), :amount], -1),
      %{},
      nil
    ]

    for invalid <- bad_requests do
      assert {:error, reason} = Native.build_transaction(invalid)
      refute reason =~ "panic"
    end

    assert {:ok, _} = Native.build_transaction(request)
  end
end
