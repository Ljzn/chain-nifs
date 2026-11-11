defmodule Parano1dNif.WireTest do
  use ExUnit.Case, async: false
  alias Parano1dNif, as: API
  alias Parano1dNif.Fixtures, as: F

  test "one input wire uses little endian slots, amount, creation id and empty dummy records" do
    request = F.request(1)
    {:ok, artifact} = API.build_transaction(request)

    assert <<0xA3, 1::little-16, anchor::binary-size(32), 1::little-64, owner::binary-size(32),
             1::little-32, 100::little-64, 1::little-64, dummy_inputs::binary-size(140),
             100::little-32, 99::little-64, output_owner::binary-size(32),
             dummy_output::binary-size(44), 0x0D01::little-16, 0, 0::little-32>> =
             artifact.raw_transaction

    assert anchor == request.epoch_anchor
    assert owner == output_owner
    assert dummy_inputs == :binary.copy(<<0>>, 140)
    assert dummy_output == :binary.copy(<<0>>, 44)
    assert byte_size(artifact.raw_transaction) == 330
  end

  test "nine inputs use minimal two pages with one fee and correct start/end markers" do
    {:ok, artifact} = API.build_transaction(F.request(9, 2))

    assert <<0xA3, 2::little-16, page1::binary-size(323), page2::binary-size(323), 0::little-32>> =
             artifact.raw_transaction

    <<anchor1::binary-size(32), fee1::little-64, owner1::binary-size(32),
      _records1::binary-size(248), bitmap1::little-16, 0>> = page1

    <<anchor2::binary-size(32), fee2::little-64, owner2::binary-size(32), 9::little-32,
      100::little-64, 9::little-64, dummy_records::binary-size(228), bitmap2::little-16, 0>> =
      page2

    assert fee1 == 1 and fee2 == 0
    assert anchor1 == anchor2 and owner1 == owner2
    assert bitmap1 == 0x07FF
    assert bitmap2 == 0x0801
    assert dummy_records == :binary.copy(<<0>>, 228)
  end
end
