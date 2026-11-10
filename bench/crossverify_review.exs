# Independent wallet verification covers maximum shape and non-default sequences.
fixture = Jason.decode!(File.read!("test/fixtures/wallet-oracle-v1.json"))
key = Enum.find(fixture["keygen"], &(&1["id"] == "ascending32"))
seed = Base.decode16!(key["seedHex"], case: :lower)
{:ok, pk} = TensorCashNif.public_key(seed)
{:ok, own} = TensorCashNif.derive_address(pk, :regtest)

payments =
  for n <- [1, 64] do
    inputs =
      for i <- 0..(n - 1) do
        %{
          txid: Base.encode16(:crypto.hash(:sha256, "review prevout #{i}"), case: :lower),
          vout: i,
          amount: 100_000,
          sequence: Enum.at([0, 0xFFFFFFFD, 0xFFFFFFFF], rem(i, 3))
        }
      end

    outputs = List.duplicate(%{address: own.address, amount: div(n * 100_000, 16)}, 16)
    {:ok, signed} = TensorCashNif.build_payment(seed, :regtest, inputs, outputs)

    {:ok, true} =
      TensorCashNif.verify_payment(
        Base.decode16!(signed.raw_hex, case: :lower),
        pk,
        :regtest,
        inputs
      )

    %{
      rawTxHex: signed.raw_hex,
      publicKeyHex: Base.encode16(pk, case: :lower),
      inputs:
        Enum.map(inputs, &Map.update!(&1, :amount, fn amount -> Integer.to_string(amount) end))
    }
  end

File.mkdir_p!("results/generated")

File.write!(
  "results/generated/review-payments.json",
  Jason.encode!(%{schemaVersion: 1, payments: payments})
)

IO.puts("Wrote 1x16 and 64x16 signed payments with non-default sequences")
