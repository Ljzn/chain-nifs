# ERL_FLAGS='+S 2:2' MIX_ENV=prod mix run bench/run.exs [bench/results.json]
# Each invocation starts a new VM. "cold" means the first call for that shape;
# only the first shape is also cold for process-wide native caches.
Code.require_file("../test/support/fixtures.ex", __DIR__)

defmodule Parano1dNif.Benchmark do
  alias Parano1dNif, as: API
  alias Parano1dNif.Fixtures, as: F

  def run do
    scenarios = Enum.map([1, 2, 9], &scenario/1)
    concurrency = concurrency_check()

    %{
      schema_version: 1,
      generated_at: DateTime.utc_now() |> DateTime.to_iso8601(),
      elixir: System.version(),
      otp: to_string(:erlang.system_info(:otp_release)),
      schedulers_online: :erlang.system_info(:schedulers_online),
      dirty_cpu_schedulers: :erlang.system_info(:dirty_cpu_schedulers_online),
      authorization_version: 4,
      native_max_concurrency: 1,
      rayon_threads: 2,
      rayon_lifetime: "per-call scoped workers; joined before NIF return",
      native_build_mode: "release",
      upstream_sha: upstream_sha(),
      authorize_includes: "proof generation and complete self-verification",
      rss_note: "process RSS samples include native memory; use /usr/bin/time -l for peak RSS",
      cold_definition: "first call per shape; only inputs=1 has process-cold native caches",
      duration_unit: "microsecond",
      memory_unit: "byte",
      process_rss_null_means: "own-process ps sampling unavailable; use external peak RSS",
      scenarios: scenarios,
      concurrency_check: concurrency
    }
  end

  defp scenario(count) do
    output_count = if count == 9, do: 2, else: 1
    {:ok, unsigned} = API.build_transaction(F.request(count, output_count))

    {cold_prove, signed} =
      measure(fn -> API.authorize_transaction(unsigned.raw_transaction, F.secret()) end)

    {cold_verify, verified} = measure(fn -> API.verify_transaction(signed.raw_transaction) end)

    {warm_prove, again} =
      measure(fn -> API.authorize_transaction(unsigned.raw_transaction, F.secret()) end)

    {warm_verify, warm_verified} =
      measure(fn -> API.verify_transaction(again.raw_transaction) end)

    unless signed.txid == unsigned.txid and signed.txid == verified.txid and
             again.txid == signed.txid and warm_verified.txid == signed.txid do
      raise "transaction id changed across proof/verify"
    end

    %{
      inputs: count,
      outputs: output_count,
      pages: signed.page_count,
      unsigned_bytes: byte_size(unsigned.raw_transaction),
      raw_bytes: byte_size(signed.raw_transaction),
      proof_bytes: signed.authorization_bytes,
      warm_raw_bytes: byte_size(again.raw_transaction),
      warm_proof_bytes: again.authorization_bytes,
      txid: signed.txid,
      proofs_differ: signed.raw_transaction != again.raw_transaction,
      prove: %{cold: cold_prove, warm: warm_prove},
      verify: %{cold: cold_verify, warm: warm_verify}
    }
  end

  defp measure(fun) do
    before = memory()
    {microseconds, result} = :timer.tc(fun)
    after_memory = memory()

    case result do
      {:ok, artifact} ->
        {%{
           duration_us: microseconds,
           beam_memory_before: before,
           beam_memory_after: after_memory
         }, artifact}

      {:error, reason} ->
        raise "native benchmark failed: #{reason}"
    end
  end

  defp memory do
    beam = Map.new(:erlang.memory())
    {:memory, process_bytes} = Process.info(self(), :memory)

    beam
    |> Map.put(:caller_process, process_bytes)
    |> Map.put(:process_rss_bytes, process_rss_bytes())
  end

  defp process_rss_bytes do
    case System.cmd("ps", ["-o", "rss=", "-p", System.pid()]) do
      {output, 0} -> String.trim(output) |> String.to_integer() |> Kernel.*(1024)
      {_output, _status} -> nil
    end
  end

  defp upstream_sha do
    path = Path.expand("vendor/parano1d", File.cwd!())

    case System.cmd("git", ["-C", path, "rev-parse", "HEAD"]) do
      {sha, 0} -> String.trim(sha)
      {_output, status} -> raise "upstream revision lookup failed: #{status}"
    end
  end

  defp concurrency_check do
    {:ok, unsigned} = API.build_transaction(F.request(1))
    task = Task.async(fn -> API.authorize_transaction(unsigned.raw_transaction, F.secret()) end)
    await_busy(task, System.monotonic_time(:millisecond) + 30_000)

    {overlap_us, overlap} =
      :timer.tc(fn ->
        API.authorize_transaction(unsigned.raw_transaction, F.secret())
      end)

    unless overlap == {:error, "busy"}, do: raise("native gate admitted overlapping work")
    {:ok, signed} = Task.await(task, 600_000)
    {first, _} = measure(fn -> API.verify_transaction(signed.raw_transaction) end)
    {second, _} = measure(fn -> API.verify_transaction(signed.raw_transaction) end)
    if API.proof_busy?(), do: raise("native admission gate remained locked")

    %{
      overlap_result: "busy",
      overlap_duration_us: overlap_us,
      sequential_verifications: [first, second],
      gate_released: true
    }
  end

  defp await_busy(task, deadline) do
    cond do
      API.proof_busy?() ->
        :ok

      System.monotonic_time(:millisecond) >= deadline ->
        raise "proof did not enter native gate"

      true ->
        case Task.yield(task, 0) do
          nil ->
            :erlang.yield()
            await_busy(task, deadline)

          _ ->
            raise "proof completed before gate observation"
        end
    end
  end
end

output = List.first(System.argv()) || Path.join(__DIR__, "results.json")
json = Jason.encode!(Parano1dNif.Benchmark.run(), pretty: true)
File.write!(output, json <> "\n")
IO.puts(json)
