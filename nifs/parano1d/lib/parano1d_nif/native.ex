defmodule Parano1dNif.Native do
  @moduledoc false
  use Rustler, otp_app: :parano1d_nif, crate: :parano1d_nif, mode: :release

  def proof_busy, do: :erlang.nif_error(:nif_not_loaded)
  def proof_status, do: :erlang.nif_error(:nif_not_loaded)
  def limits, do: :erlang.nif_error(:nif_not_loaded)

  def derive_address(_secret32), do: :erlang.nif_error(:nif_not_loaded)
  def build_transaction(_request), do: :erlang.nif_error(:nif_not_loaded)

  def authorize_transaction(_unsigned_raw_binary, _secret32, _version),
    do: :erlang.nif_error(:nif_not_loaded)

  def verify_transaction(_raw_binary, _version), do: :erlang.nif_error(:nif_not_loaded)
end
