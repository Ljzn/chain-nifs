defmodule TensorCashNif.TestOracle do
  import ExUnit.Assertions

  @fixtures Path.expand("../fixtures", __DIR__)
  def fixture(name \\ "wallet-oracle-v1.json") do
    @fixtures |> Path.join(name) |> File.read!() |> Jason.decode!()
  end

  def hex(value), do: Base.decode16!(value, case: :mixed)
  def key(oracle, id), do: Enum.find(oracle["keygen"], &(&1["id"] == id))

  def payment(oracle, tx) do
    key = key(oracle, hd(tx["inputs"])["keyId"])

    inputs =
      Enum.map(tx["inputs"], fn row ->
        %{
          txid: row["txid"],
          vout: row["vout"],
          amount: String.to_integer(row["valueSats"]),
          sequence: row["sequence"]
        }
      end)

    outputs =
      Enum.map(tx["outputs"], fn row ->
        address =
          Enum.find(oracle["addresses"], fn a ->
            a["network"] == tx["network"] and a["scriptPubKeyHex"] == row["scriptPubKeyHex"]
          end)

        assert address, "oracle output needs a matching address row"
        %{address: address["address"], amount: String.to_integer(row["valueSats"])}
      end)

    %{
      seed: hex(key["seedHex"]),
      pk: hex(key["publicKeyHex"]),
      network: tx["network"],
      inputs: inputs,
      outputs: outputs,
      raw: hex(tx["rawTxHex"])
    }
  end

  def flip(binary, offset) do
    <<prefix::binary-size(^offset), byte, rest::binary>> = binary
    prefix <> <<Bitwise.bxor(byte, 1)>> <> rest
  end

  def replace(binary, offset, replacement) do
    replacement_size = byte_size(replacement)
    <<prefix::binary-size(^offset), _::binary-size(^replacement_size), rest::binary>> = binary
    prefix <> replacement <> rest
  end

  def rejected(result) do
    assert match?({:error, _}, result) or result == {:ok, false},
           "expected rejection, received: #{inspect(result)}"
  end
end
