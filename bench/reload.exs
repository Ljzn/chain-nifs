# Run only in a disposable BEAM: this deliberately unloads the native module.
unless Code.ensure_loaded?(Parano1dNif.Fixtures) do
  Code.require_file("../test/support/fixtures.ex", __DIR__)
end

alias Parano1dNif, as: API
alias Parano1dNif.Fixtures, as: F

module = Parano1dNif.Native
{:module, ^module} = Code.ensure_loaded(module)
{^module, beam, filename} = :code.get_object_code(module)
{:ok, unsigned} = API.build_transaction(F.request(1))

for iteration <- 1..3 do
  {:ok, signed} = API.authorize_transaction(unsigned.raw_transaction, F.secret())
  false = API.proof_busy?()
  true = :code.delete(module)
  true = :code.soft_purge(module)
  false = :erlang.check_old_code(module)
  false = :code.is_loaded(module)
  {:module, ^module} = :code.load_binary(module, filename, beam)
  {:ok, verified} = API.verify_transaction(signed.raw_transaction)
  true = verified.txid == signed.txid
  false = API.proof_busy?()
  IO.puts("prove / unload / reload / verify cycle #{iteration}: passed")
end
