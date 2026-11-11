defmodule BlocknetNif.Native do
  @moduledoc false
  use Rustler, otp_app: :blocknet_nif, crate: :blocknet_nif, mode: :release
  def seeded_secret(_seed), do: :erlang.nif_error(:nif_not_loaded)
  def public_key(_secret), do: :erlang.nif_error(:nif_not_loaded)
  def key_image(_secret), do: :erlang.nif_error(:nif_not_loaded)
  def derive_keys(_seed), do: :erlang.nif_error(:nif_not_loaded)
  def commitment(_amount, _blind), do: :erlang.nif_error(:nif_not_loaded)
  def range_prove(_amount, _blind), do: :erlang.nif_error(:nif_not_loaded)
  def range_verify(_commitment, _proof), do: :erlang.nif_error(:nif_not_loaded)

  def ring_sign(_keys, _commits, _index, _secret, _blind, _pseudo, _pseudo_blind, _message),
    do: :erlang.nif_error(:nif_not_loaded)

  def ring_verify(_keys, _commits, _message, _signature), do: :erlang.nif_error(:nif_not_loaded)

  def build_payment(_view, _network, _inputs, _outputs, _fee),
    do: :erlang.nif_error(:nif_not_loaded)

  def verify_payment(_raw), do: :erlang.nif_error(:nif_not_loaded)
  def receive_payment(_raw, _spend, _view, _network), do: :erlang.nif_error(:nif_not_loaded)
end
