defmodule BlocknetNif.OfficialVectorsTest do
  use ExUnit.Case, async: false
  alias BlocknetNif, as: N
  alias BlocknetNif.Synthetic, as: S
  @moduletag timeout: 180_000
  setup_all do
    fixture =
      Path.join(__DIR__, "fixtures/official_vectors.json") |> File.read!() |> Jason.decode!()

    %{fixture: fixture}
  end

  test "official seeded private/public vectors and wallet derivation match exactly", %{fixture: f} do
    for v <- f["key_vectors"] do
      assert {:ok, private} = N.seeded_secret(S.unhex(v["seed_hex"]))
      assert S.hex(private) == v["private_hex"]
      assert {:ok, public} = N.public_key(private)
      assert S.hex(public) == v["public_hex"]
    end

    s = f["stealth"]
    assert {:ok, wallet} = N.derive_keys(S.unhex(s["wallet_seed64_hex"]))
    assert wallet.spend_secret_hex == s["spend_private_hex"]
    assert wallet.view_secret_hex == s["view_private_hex"]
    assert wallet.spend_public_hex == s["spend_public_hex"]
    assert wallet.view_public_hex == s["view_public_hex"]
  end

  test "official RingCT signatures and range proofs verify through real NIF", %{fixture: f} do
    assert f["cases"] != []

    for c <- f["cases"] do
      assert {:ok, true} =
               N.ring_verify(
                 c["ring_keys"],
                 c["ring_commitments"],
                 S.unhex(c["message_hex"]),
                 S.unhex(c["signature_hex"])
               )
    end

    for o <- f["stealth"]["outputs"] do
      assert {:ok, commitment} = N.commitment(o["amount"], S.unhex(o["blinding_raw_hex"]))
      assert S.hex(commitment) == o["commitment_hex"]
      assert {:ok, true} = N.range_verify(commitment, S.unhex(o["range_proof_hex"]))
    end
  end

  test "official raw payment verifies and recovers exact indexed secrets memos and blindings", %{
    fixture: f
  } do
    assert f["payments"] != []

    for p <- f["payments"] do
      raw = S.unhex(p["raw_hex"])
      assert {:ok, true} = N.verify_payment(raw)
      receiver = p["receiver"]

      assert {:ok, received} =
               N.receive_payment(
                 raw,
                 S.unhex(receiver["spend_private_hex"]),
                 S.unhex(receiver["view_private_hex"]),
                 "mainnet"
               )

      assert length(received) == length(f["stealth"]["outputs"])

      for {got, expected} <- Enum.zip(received, f["stealth"]["outputs"]) do
        assert got.index == expected["index"]
        assert got.amount == expected["amount"]
        assert got.memo_valid
        assert got.memo_hex == expected["memo_hex"]
        assert got.secret_hex == expected["one_time_private_hex"]
        assert got.blinding_hex == expected["blinding_raw_hex"]
        assert {:ok, public} = N.public_key(S.unhex(got.secret_hex))
        assert S.hex(public) == expected["one_time_public_hex"]
      end
    end
  end
end
