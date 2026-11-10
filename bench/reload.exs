# Normal-path reload only: this is not a native-crash recovery guarantee.
seed = :binary.copy(<<7>>, 32)
msg = :crypto.hash(:sha256, "reload fixture")
module = TensorCashNif.Native

for n <- 1..3 do
  {:ok, pk} = TensorCashNif.public_key(seed)
  {:ok, sig} = TensorCashNif.sign(seed, msg)
  true = :code.delete(module)
  true = :code.soft_purge(module)
  false = :erlang.check_old_code(module)
  {:module, ^module} = :code.load_file(module)
  {:ok, true} = TensorCashNif.verify(pk, msg, sig)
  IO.puts("sign / unload / reload / verify cycle #{n}: passed")
end
