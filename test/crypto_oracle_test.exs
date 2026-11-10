defmodule TensorCashNif.CryptoOracleTest do
  use ExUnit.Case, async: false
  import TensorCashNif.TestOracle
  alias TensorCashNif, as: Nif

  test "seeded public keys match official wallet and NIST ACVP vectors" do
    for row <- fixture()["keygen"] do
      assert Nif.public_key(hex(row["seedHex"])) == {:ok, hex(row["publicKeyHex"])}
    end

    for row <- fixture("mldsa65-acvp-fips204.json")["keyGen"] do
      assert Nif.public_key(hex(row["seed"])) == {:ok, hex(row["pk"])}
    end
  end

  test "official deterministic and fixed-randomness signatures verify" do
    oracle = fixture()

    for row <- oracle["signatures"] do
      pk = hex(key(oracle, row["keyId"])["publicKeyHex"])
      assert Nif.verify(pk, hex(row["msg32Hex"]), hex(row["signatureHex"])) == {:ok, true}
    end
  end

  test "captured Core liboqs signatures verify" do
    for row <- fixture("core-mldsa65-signature.json")["cases"] do
      assert Nif.verify(hex(row["publicKey"]), hex(row["digest"]), hex(row["signature"])) ==
               {:ok, true}
    end
  end

  test "fresh hedged signatures differ and verify under the seeded key" do
    row = hd(fixture()["keygen"])
    seed = hex(row["seedHex"])
    pk = hex(row["publicKeyHex"])
    digest = :crypto.hash(:sha256, "synthetic TensorCash signing test")
    assert {:ok, first} = Nif.sign(seed, digest)
    assert {:ok, second} = Nif.sign(seed, digest)
    assert byte_size(first) == 3309
    assert byte_size(second) == 3309
    refute first == second
    assert Nif.verify(pk, digest, first) == {:ok, true}
    assert Nif.verify(pk, digest, second) == {:ok, true}
    assert Nif.verify(pk, flip(digest, 0), first) == {:ok, false}
    rejected(Nif.verify(pk, digest, flip(first, 0)))
    rejected(Nif.verify(flip(pk, 0), digest, first))
  end

  test "wrong binary lengths and nonbinary crypto arguments are rejected" do
    pk = hex(hd(fixture()["keygen"])["publicKeyHex"])
    digest = <<0::256>>
    sig = :binary.copy(<<0>>, 3309)

    for bad <- [nil, [], <<>>, <<0::248>>, <<0::264>>] do
      assert {:error, _} = Nif.public_key(bad)
      assert {:error, _} = Nif.sign(<<0::256>>, bad)
      assert {:error, _} = Nif.verify(pk, bad, sig)
    end

    for bad <- [<<>>, binary_part(pk, 0, 1951), pk <> <<0>>] do
      assert {:error, _} = Nif.verify(bad, digest, sig)
    end

    for bad <- [<<>>, binary_part(sig, 0, 3308), sig <> <<0>>] do
      assert {:error, _} = Nif.verify(pk, digest, bad)
    end
  end

  test "spending seed matches official mnemonic derivation in display genesis order" do
    d = fixture()["derivation"]

    args = [
      hex(d["bip39SeedHex"]),
      hex(d["genesisHex"]),
      d["account"],
      hex(d["policyIdHex"]),
      d["branch"],
      d["index"]
    ]

    assert apply(Nif, :spending_seed, args) == {:ok, hex(d["spendingSeedHex"])}
    assert {:ok, changed} = apply(Nif, :spending_seed, List.replace_at(args, 5, d["index"] + 1))
    refute changed == hex(d["spendingSeedHex"])

    for {position, value} <- [
          {0, <<0>>},
          {1, <<0>>},
          {2, -1},
          {2, 0x100000000},
          {3, <<0>>},
          {4, 2},
          {5, -1},
          {5, 0x100000000}
        ] do
      assert {:error, _} = apply(Nif, :spending_seed, List.replace_at(args, position, value))
    end
  end

  test "all six official address rows match every exposed descriptor field" do
    oracle = fixture()
    assert length(oracle["addresses"]) == 6

    fields = [
      address: "address",
      script_pubkey_hex: "scriptPubKeyHex",
      leaf_script_hex: "leafScriptHex",
      control_block_hex: "controlBlockHex",
      output_key_hex: "outputKeyHex",
      leaf_hash_hex: "leafHashHex"
    ]

    for row <- oracle["addresses"] do
      pk = hex(key(oracle, row["keyId"])["publicKeyHex"])
      expected = Map.new(fields, fn {native, official} -> {native, Map.fetch!(row, official)} end)
      assert Nif.derive_address(pk, row["network"]) == {:ok, expected}
      assert Nif.derive_address(pk, String.to_existing_atom(row["network"])) == {:ok, expected}
    end
  end
end
