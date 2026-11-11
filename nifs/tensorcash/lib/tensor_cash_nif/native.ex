defmodule TensorCashNif.Native do
  @moduledoc false
  use Rustler,
      [otp_app: :tensorcash_nif, crate: :tensorcash_nif, mode: :release] ++
        TensorCashNif.Precompiled.rustler_options!(Path.expand("../..", __DIR__))

  def public_key(_seed), do: :erlang.nif_error(:nif_not_loaded)
  def sign(_seed, _digest), do: :erlang.nif_error(:nif_not_loaded)
  def verify(_pk, _digest, _sig), do: :erlang.nif_error(:nif_not_loaded)

  def spending_seed(_seed64, _genesis, _account, _policy, _branch, _index),
    do: :erlang.nif_error(:nif_not_loaded)

  def identity_seed(_seed64, _genesis, _account), do: :erlang.nif_error(:nif_not_loaded)
  def derive_address(_pk, _network), do: :erlang.nif_error(:nif_not_loaded)
  def build_payment(_seed, _network, _inputs, _outputs), do: :erlang.nif_error(:nif_not_loaded)
  def unsigned_payment(_pk, _network, _inputs, _outputs), do: :erlang.nif_error(:nif_not_loaded)
  def verify_payment(_raw, _pk, _network, _inputs), do: :erlang.nif_error(:nif_not_loaded)
end
