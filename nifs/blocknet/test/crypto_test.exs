defmodule BlocknetNif.CryptoTest do
  use ExUnit.Case, async: false
  alias BlocknetNif, as: N
  alias BlocknetNif.Synthetic, as: S

  @order 7_237_005_577_332_262_213_973_186_563_042_994_240_857_116_359_379_907_606_001_950_938_285_454_250_989

  test "seeded secret exactly reduces SHA512 blocknet_keygen in little endian" do
    for seed <- [<<0::256>>, <<255::256>>, S.seed("seed-vector")] do
      expected =
        rem(
          :binary.decode_unsigned(:crypto.hash(:sha512, "blocknet_keygen" <> seed), :little),
          @order
        )

      encoded = :binary.encode_unsigned(expected, :little)
      assert {:ok, secret} = N.seeded_secret(seed)
      assert secret == encoded <> :binary.copy(<<0>>, 32 - byte_size(encoded))
      assert {:ok, pk} = N.public_key(secret)
      assert byte_size(pk) == 32
      assert {:ok, image} = N.key_image(secret)
      assert byte_size(image) == 32
    end
  end

  test "wallet derivation requires 64 bytes and returns matching public keys" do
    seed = :crypto.hash(:sha512, "wallet-vector")
    assert {:ok, keys} = N.derive_keys(seed)
    assert {:ok, ^keys} = N.derive_keys(seed)
    assert {:error, _} = N.derive_keys(binary_part(seed, 0, 32))
    assert {:error, _} = BlocknetNif.Native.derive_keys(binary_part(seed, 0, 32))

    for prefix <- [:spend, :view] do
      secret = Map.fetch!(keys, String.to_existing_atom("#{prefix}_secret_hex")) |> S.unhex()
      public = Map.fetch!(keys, String.to_existing_atom("#{prefix}_public_hex")) |> S.unhex()
      assert byte_size(secret) == 32
      assert :binary.decode_unsigned(secret, :little) in 1..(@order - 1)
      assert {:ok, ^public} = N.public_key(secret)
    end
  end

  test "range proofs cover zero and u64 maximum and bind the commitment" do
    blind = S.secret("range")

    for amount <- [0, 0xFFFFFFFFFFFFFFFF] do
      assert {:ok, commitment} = N.commitment(amount, blind)
      assert {:ok, proof} = N.range_prove(amount, blind)
      assert byte_size(proof) <= 1024
      assert {:ok, true} = N.range_verify(commitment, proof)
      assert {:ok, other} = N.commitment(Bitwise.bxor(amount, 1), blind)
      assert {:ok, false} = N.range_verify(other, proof)
      assert_rejected(N.range_verify(commitment, S.flip(proof, div(byte_size(proof), 2))))
      assert_rejected(N.range_verify(commitment, binary_part(proof, 0, byte_size(proof) - 1)))
    end

    assert {:ok, <<0::256>>} = N.commitment(0, <<0::256>>)
  end

  test "ring signatures bind message, ring order, commitments and pseudo output" do
    r = S.ring("ring-binding", 15)
    assert {:ok, signature} = S.sign(r)
    assert byte_size(signature) == 1120
    i = r.input
    assert {:ok, true} = N.ring_verify(i.ring_keys, i.ring_commitments, r.message, signature)

    assert {:ok, false} =
             N.ring_verify(i.ring_keys, i.ring_commitments, S.flip(r.message, 0), signature)

    assert_rejected(
      N.ring_verify(Enum.reverse(i.ring_keys), i.ring_commitments, r.message, signature)
    )

    assert_rejected(
      N.ring_verify(i.ring_keys, Enum.reverse(i.ring_commitments), r.message, signature)
    )

    assert {:ok, wrong_pseudo} = N.commitment(101, r.pseudo_blind)
    assert {:error, _} = S.sign(%{r | pseudo: wrong_pseudo})
    assert {:error, _} = S.sign(%{r | secret: S.secret("wrong-signer")})
    assert {:error, _} = S.sign(%{r | pseudo_blind: S.secret("wrong-pseudo-blind")})

    for offset <- [0, 31, 32, 543, 1056, 1088, 1119] do
      assert_rejected(
        N.ring_verify(i.ring_keys, i.ring_commitments, r.message, S.flip(signature, offset))
      )
    end
  end

  test "bounded concurrent real ring roundtrips keep witnesses independent" do
    rings = for index <- [0, 3, 8, 15], do: S.ring("concurrent-#{index}", index)

    results =
      Task.async_stream(
        rings,
        fn r ->
          {:ok, signature} = S.sign(r)
          N.ring_verify(r.input.ring_keys, r.input.ring_commitments, r.message, signature)
        end,
        max_concurrency: 4,
        timeout: 120_000
      )
      |> Enum.to_list()

    assert results == List.duplicate({:ok, {:ok, true}}, 4)
  end

  defp assert_rejected(result), do: assert(result == {:ok, false} or match?({:error, _}, result))
end
