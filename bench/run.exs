# Run after compiling: mix run bench/run.exs
# BLOCKNET_BENCH_MAX=1 includes one costly 16-input/16-output build and export.
# Every key and UTXO below is synthetic and has no chain provenance.
Code.require_file("../test/support/synthetic.ex", __DIR__)

defmodule BlocknetNif.Bench do
  alias BlocknetNif, as: N
  alias BlocknetNif.Synthetic, as: S

  def run do
    iterations =
      System.get_env("BLOCKNET_BENCH_ITERATIONS", "3") |> String.to_integer() |> max(1) |> min(9)

    max_case = System.get_env("BLOCKNET_BENCH_MAX") == "1"
    IO.puts("Real Blocknet NIF benchmark; synthetic prepared UTXOs, monotonic milliseconds")
    IO.puts("Iterations: #{iterations}; optional 16x16: #{max_case}")
    ring = S.ring("benchmark-ring")
    {sign_measure, {:ok, signature}} = measure("ring_sign/16", iterations, fn -> S.sign(ring) end)

    {verify_measure, {:ok, true}} =
      measure("ring_verify/16", iterations, fn ->
        N.ring_verify(ring.input.ring_keys, ring.input.ring_commitments, ring.message, signature)
      end)

    blind = S.secret("benchmark-proof")
    {:ok, commitment} = N.commitment(100, blind)

    {proof_measure, {:ok, proof}} =
      measure("range_prove/64bit", iterations, fn -> N.range_prove(100, blind) end)

    {proof_verify_measure, {:ok, true}} =
      measure("range_verify/64bit", iterations, fn -> N.range_verify(commitment, proof) end)

    sizes = [{1, 2}, {2, 2}, {16, 2}] ++ if(max_case, do: [{16, 16}], else: [])

    {measurements, payments} =
      Enum.reduce(sizes, {[], []}, fn {ni, no}, {metrics, samples} ->
        p = S.payment(ni, no, "benchmark-#{ni}x#{no}")
        count = if(no == 16, do: 1, else: iterations)
        {build_metric, {:ok, payment}} = measure("build/#{ni}x#{no}", count, fn -> S.build(p) end)
        raw = S.unhex(payment.raw_hex)

        {verify_metric, {:ok, true}} =
          measure("verify/#{ni}x#{no}", count, fn -> N.verify_payment(raw) end)

        {receive_metric, {:ok, received}} =
          measure("receive/#{ni}x#{no}", count, fn -> S.receive(raw, p.receiver) end)

        expected_received =
          p.outputs
          |> Enum.with_index()
          |> Enum.map(fn {output, index} ->
            %{index: index, amount: output.amount, memo_hex: output.memo_hex}
          end)

        actual_received = Enum.map(received, &Map.take(&1, [:index, :amount, :memo_hex]))

        unless actual_received == expected_received and Enum.all?(received, & &1.memo_valid),
          do: raise("recovered outputs differ from planned amounts, memos or memo validity")

        sample = %{
          raw_hex: payment.raw_hex,
          receiver: %{
            spend_private_hex: p.receiver.spend_secret_hex,
            view_private_hex: p.receiver.view_secret_hex
          },
          network: "mainnet",
          expected_received: expected_received
        }

        IO.puts("  #{ni}x#{no}: #{payment.bytes} wire bytes; fee #{payment.fee}")

        {metrics ++ [Map.put(build_metric, :bytes, payment.bytes), verify_metric, receive_metric],
         samples ++ [sample]}
      end)

    results = %{
      synthetic_only: true,
      clock: "System.monotonic_time",
      unit: "milliseconds",
      iterations: iterations,
      max_case_enabled: max_case,
      measurements:
        [sign_measure, verify_measure, proof_measure, proof_verify_measure] ++ measurements
    }

    exports = %{
      cases: [
        %{
          message_hex: S.hex(ring.message),
          ring_keys: ring.input.ring_keys,
          ring_commitments: ring.input.ring_commitments,
          signature_hex: S.hex(signature)
        }
      ],
      payments: payments
    }

    File.mkdir_p!("results/generated")
    File.write!("results/generated/benchmark.json", Jason.encode!(results, pretty: true) <> "\n")

    File.write!(
      "results/generated/native-sample.json",
      Jason.encode!(exports, pretty: true) <> "\n"
    )

    IO.puts("Wrote results/generated/benchmark.json and results/generated/native-sample.json")

    unless max_case,
      do: IO.puts("Set BLOCKNET_BENCH_MAX=1 to include the 16x16 interoperability sample.")
  end

  defp measure(name, count, fun) do
    {durations, last} =
      Enum.reduce(1..count, {[], nil}, fn _, {times, _} ->
        started = System.monotonic_time()
        result = fun.()
        elapsed = System.monotonic_time() - started
        ms = System.convert_time_unit(elapsed, :native, :microsecond) / 1000
        {[ms | times], result}
      end)

    sorted = Enum.sort(durations)

    median =
      if rem(count, 2) == 1,
        do: Enum.at(sorted, div(count, 2)),
        else: (Enum.at(sorted, div(count, 2) - 1) + Enum.at(sorted, div(count, 2))) / 2

    IO.puts("#{String.pad_trailing(name, 22)} median #{Float.round(median, 3)} ms (n=#{count})")

    {%{name: name, samples_ms: Enum.reverse(durations), median_ms: median, iterations: count},
     last}
  end
end

BlocknetNif.Bench.run()
