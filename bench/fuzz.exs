# Reproducible bounded mutation smoke test; not a coverage-guided fuzzer or sanitizer.
unless Code.ensure_loaded?(BlocknetNif.Synthetic) do
  Code.require_file("../test/support/synthetic.ex", __DIR__)
end

alias BlocknetNif, as: N
alias BlocknetNif.Synthetic, as: S
count = String.to_integer(System.get_env("BLOCKNET_FUZZ_CASES", "256"))
seed = String.to_integer(System.get_env("BLOCKNET_FUZZ_SEED", "20261111"))

if count not in 1..4096 or seed not in 1..2_147_483_647,
  do: raise("invalid bounded fuzz configuration")

p = S.payment(1, 2, "mutation-smoke")
{:ok, payment} = S.build(p)
raw = S.unhex(payment.raw_hex)
{:ok, true} = N.verify_payment(raw)
{:ok, original} = S.receive(raw, p.receiver)
[wire | _] = S.wire_layout(raw).outputs
commitment = binary_part(raw, wire.offset + 32, 32)

check = fn api, result, reject? ->
  case result do
    {:error, "native operation panicked"} -> raise "caught native panic"
    {:error, reason} when is_binary(reason) -> :ok
    {:ok, false} when api in [:verify, :range] -> :ok
    {:ok, true} when api in [:verify, :range] and not reject? -> :ok
    {:ok, found} when api == :receive and is_list(found) and not reject? -> :ok
    other -> raise "invalid #{api} result (must reject: #{reject?}): #{inspect(other)}"
  end
end

Enum.reduce(1..count, :rand.seed_s(:exsss, {seed, seed + 1, seed + 2}), fn i, state ->
  {position, state} = :rand.uniform_s(byte_size(raw), state)
  {length, state} = :rand.uniform_s(4096, state)
  {random, state} = :rand.bytes_s(length, state)

  candidate =
    case rem(i, 8) do
      0 -> random
      1 -> S.flip(raw, position - 1)
      2 -> binary_part(raw, 0, position - 1)
      3 -> raw <> random
      4 -> S.replace(raw, 33, <<0xFFFFFFFF::little-32>>)
      5 -> S.replace(raw, wire.offset + 200, <<0xFFFFFFFF::little-32>>)
      6 -> :binary.copy(<<255>>, 131_073)
      7 -> S.replace(raw, 37, <<0::little-32>>)
    end

  # Use Native directly so the Elixir wrapper cannot hide decoder/parser failures.
  # These modes violate structural bounds independently of cryptographic validity.
  reject? = rem(i, 8) in [2, 3, 4, 5, 6, 7]
  check.(:verify, N.Native.verify_payment(candidate), reject?)

  check.(
    :receive,
    N.Native.receive_payment(
      candidate,
      S.unhex(p.receiver.spend_secret_hex),
      S.unhex(p.receiver.view_secret_hex),
      "mainnet"
    ),
    reject?
  )

  check.(:range, N.Native.range_verify(commitment, random), false)
  state
end)

# Check that previous malformed calls did not corrupt the NIF's state.
{:ok, true} = N.verify_payment(raw)
{:ok, ^original} = S.receive(raw, p.receiver)

IO.puts(
  Jason.encode!(%{
    valid: true,
    cases: count,
    seed: seed,
    nif_calls: 3 * count,
    mode: "bounded mutation smoke; no sanitizer/coverage-guided claims"
  })
)
