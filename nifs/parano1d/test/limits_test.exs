defmodule Parano1dNif.LimitsTest do
  use ExUnit.Case, async: false
  alias Parano1dNif, as: API
  alias Parano1dNif.Native
  alias Parano1dNif.Fixtures, as: F

  test "wrapper and native enforce identical published size and count budgets" do
    assert API.limits() == Native.limits()
    limits = API.limits()
    assert limits.max_unsigned_bytes == 7 + limits.max_pages * limits.page_bytes
    assert limits.max_raw_bytes == API.max_raw_bytes()
    assert limits.max_address_bytes == 100
    request = F.request(1)

    for size <- [101, 128, 129] do
      invalid = %{request | owner: :binary.copy(<<97>>, size)}
      assert {:error, _} = API.build_transaction(invalid)
      assert {:error, _} = Native.build_transaction(invalid)
    end

    assert API.proof_status() == "idle"
    refute API.proof_busy?()
  end
end
