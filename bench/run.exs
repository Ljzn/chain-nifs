# Only public, synthetic fixture seeds are used by this benchmark.
fixture = Jason.decode!(File.read!("test/fixtures/wallet-oracle-v1.json"))
key = Enum.find(fixture["keygen"], &(&1["id"] == "ascending32"))
seed = Base.decode16!(key["seedHex"], case: :lower)
{:ok, pk} = TensorCashNif.public_key(seed)
digest = :crypto.hash(:sha256, "tensorcash native benchmark")

measure = fn fun, n ->
  samples =
    for _ <- 1..n do
      {us, {:ok, _}} = :timer.tc(fun)
      us
    end

  sorted = Enum.sort(samples)

  %{
    samples: n,
    min_us: hd(sorted),
    median_us: Enum.at(sorted, div(n, 2)),
    max_us: List.last(sorted)
  }
end

{:ok, sig} = TensorCashNif.sign(seed, digest)

crypto = %{
  public_key: measure.(fn -> TensorCashNif.public_key(seed) end, 31),
  sign_including_keygen_selfverify: measure.(fn -> TensorCashNif.sign(seed, digest) end, 31),
  verify: measure.(fn -> TensorCashNif.verify(pk, digest, sig) end, 31)
}

{:ok, own} = TensorCashNif.derive_address(pk, :regtest)
other = fixture["keygen"] |> hd() |> Map.fetch!("publicKeyHex") |> Base.decode16!(case: :lower)
{:ok, recipient} = TensorCashNif.derive_address(other, :regtest)

for_inputs = fn n ->
  for i <- 1..n do
    %{
      txid: Base.encode16(:crypto.hash(:sha256, "synthetic prevout #{i}"), case: :lower),
      vout: 0,
      amount: 100_000,
      sequence: 0xFFFFFFFD
    }
  end
end

payments =
  for n <- [1, 2, 64] do
    ins = for_inputs.(n)

    outs = [
      %{address: recipient.address, amount: 50_000},
      %{address: own.address, amount: n * 100_000 - 60_000}
    ]

    timing = measure.(fn -> TensorCashNif.build_payment(seed, :regtest, ins, outs) end, 5)
    {:ok, built} = TensorCashNif.build_payment(seed, :regtest, ins, outs)
    raw = Base.decode16!(built.raw_hex, case: :lower)
    {:ok, true} = TensorCashNif.verify_payment(raw, pk, :regtest, ins)
    verification = measure.(fn -> TensorCashNif.verify_payment(raw, pk, :regtest, ins) end, 5)

    %{
      inputs: n,
      outputs: 2,
      build: timing,
      verify: verification,
      bytes: byte_size(raw),
      weight: built.weight,
      vsize: built.vsize,
      fee: built.fee
    }
  end

# Feed actual randomized NIF signatures/payments to the independent official TS modules.
cases =
  for i <- 0..7 do
    msg = :crypto.hash(:sha256, "crossverify #{i}")
    {:ok, signature} = TensorCashNif.sign(seed, msg)

    %{
      id: "native-#{i}",
      publicKeyHex: Base.encode16(pk, case: :lower),
      msg32Hex: Base.encode16(msg, case: :lower),
      signatureHex: Base.encode16(signature, case: :lower)
    }
  end

ins = for_inputs.(2)
outs = [%{address: recipient.address, amount: 80_000}, %{address: own.address, amount: 110_000}]
{:ok, built} = TensorCashNif.build_payment(seed, :regtest, ins, outs)

payload = %{
  schemaVersion: 1,
  cases: cases,
  payments: [
    %{
      rawTxHex: built.raw_hex,
      publicKeyHex: Base.encode16(pk, case: :lower),
      inputs: Enum.map(ins, &Map.update!(&1, :amount, fn n -> Integer.to_string(n) end))
    }
  ]
}

File.mkdir_p!("results")
File.write!("interop/native.local.json", Jason.encode!(payload))
File.write!("results/native-sample.json", Jason.encode!(payload))

result = %{
  runtime: %{
    otp: to_string(:erlang.system_info(:otp_release)),
    elixir: System.version(),
    schedulers: :erlang.system_info(:schedulers),
    dirty_cpu_schedulers: :erlang.system_info(:dirty_cpu_schedulers),
    architecture: to_string(:erlang.system_info(:system_architecture))
  },
  crypto: crypto,
  payments: payments,
  beam_memory_at_end_bytes: :erlang.memory(:total),
  note:
    "warm release samples; sign includes seed keygen+selfverify; overall RSS is measured externally, not per-call delta"
}

File.mkdir_p!("results")
File.write!("results/benchmark.json", Jason.encode!(result, pretty: true))
IO.puts(Jason.encode!(result, pretty: true))
