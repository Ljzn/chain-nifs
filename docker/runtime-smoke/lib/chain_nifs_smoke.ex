defmodule ChainNifsSmoke do
  @moduledoc false

  def run do
    for tool <- ~w(rustc cargo rustup cmake gcc cc make go node npm) do
      if System.find_executable(tool), do: raise("Unexpected build tool: #{tool}")
    end

    secret = :binary.copy(<<7>>, 32)
    {:ok, owner} = Parano1dNif.derive_address(secret)

    {:ok, unsigned} =
      Parano1dNif.build_transaction(%{
        owner: owner,
        epoch_anchor: :binary.copy(<<3>>, 32),
        fee: 1,
        inputs: [%{slot_index: 1, amount: 100, creation_id: 1}],
        outputs: [%{slot_index: 100, amount: 99, owner: owner}]
      })

    {:ok, signed} = Parano1dNif.authorize_transaction(unsigned.raw_transaction, secret)
    {:ok, verified} = Parano1dNif.verify_transaction(signed.raw_transaction)
    true = verified.txid == signed.txid
    IO.puts("Parano1d: real proof and verification passed")

    digest = :crypto.hash(:sha256, "precompiled runtime smoke")
    {:ok, pk} = TensorCashNif.public_key(secret)
    {:ok, signature} = TensorCashNif.sign(secret, digest)
    {:ok, true} = TensorCashNif.verify(pk, digest, signature)
    {:ok, false} = TensorCashNif.verify(pk, :crypto.hash(:sha256, "changed"), signature)
    IO.puts("TensorCash: ML-DSA signature and negative verification passed")

    {:ok, blind} = BlocknetNif.seeded_secret(secret)
    {:ok, commitment} = BlocknetNif.commitment(42, blind)
    {:ok, proof} = BlocknetNif.range_prove(42, blind)
    {:ok, true} = BlocknetNif.range_verify(commitment, proof)
    {:ok, other} = BlocknetNif.commitment(43, blind)
    {:ok, false} = BlocknetNif.range_verify(other, proof)
    IO.puts("Blocknet: range proof and negative verification passed")
    IO.puts("All precompiled NIFs passed without build tools")
  end
end
