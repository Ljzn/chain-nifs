defmodule BlocknetNif.Synthetic do
  @moduledoc "Synthetic prepared UTXOs only; these rings have no chain provenance."
  alias BlocknetNif, as: N
  def hex(bytes), do: Base.encode16(bytes, case: :lower)
  def unhex(text), do: Base.decode16!(text, case: :mixed)
  def seed(label), do: :crypto.hash(:sha256, "blocknet-nif-test:" <> to_string(label))

  def secret(label) do
    {:ok, secret} = N.seeded_secret(seed(label))
    secret
  end

  def wallet(label) do
    {:ok, wallet} =
      N.derive_keys(:crypto.hash(:sha512, "blocknet-nif-wallet:" <> to_string(label)))

    wallet
  end

  def input(label, amount \\ 100, index \\ 7) do
    members =
      for i <- 0..15 do
        sk = secret("#{label}:member:#{i}")
        blind = secret("#{label}:blind:#{i}")
        {:ok, pk} = N.public_key(sk)
        {:ok, commitment} = N.commitment(if(i == index, do: amount, else: i + 1), blind)
        {sk, blind, hex(pk), hex(commitment)}
      end

    {sk, blind, _, _} = Enum.at(members, index)

    %{
      secret_hex: hex(sk),
      amount: amount,
      blinding_hex: hex(blind),
      ring_keys: Enum.map(members, &elem(&1, 2)),
      ring_commitments: Enum.map(members, &elem(&1, 3)),
      real_index: index
    }
  end

  def output(wallet, amount, memo \\ "") do
    %{
      spend_public_hex: wallet.spend_public_hex,
      view_public_hex: wallet.view_public_hex,
      amount: amount,
      memo_hex: hex(memo)
    }
  end

  def ring(label, index \\ 7) do
    input = input(label, 100, index)
    pseudo_blind = secret("#{label}:pseudo")
    {:ok, pseudo} = N.commitment(input.amount, pseudo_blind)

    %{
      input: input,
      secret: unhex(input.secret_hex),
      blind: unhex(input.blinding_hex),
      pseudo: pseudo,
      pseudo_blind: pseudo_blind,
      message: seed("#{label}:message")
    }
  end

  def sign(ring, module \\ N) do
    i = ring.input

    module.ring_sign(
      i.ring_keys,
      i.ring_commitments,
      i.real_index,
      ring.secret,
      ring.blind,
      ring.pseudo,
      ring.pseudo_blind,
      ring.message
    )
  end

  def payment(input_count \\ 2, output_count \\ 2, label \\ "payment") do
    sender = wallet("#{label}:sender")
    receiver = wallet("#{label}:receiver")
    inputs = for i <- 1..input_count, do: input("#{label}:#{i}", 100, rem(i, 16))
    total = 100 * input_count - 1

    outputs =
      for i <- 1..output_count do
        amount =
          div(total, output_count) + if(i == output_count, do: rem(total, output_count), else: 0)

        output(receiver, amount, if(i == output_count, do: :binary.copy(<<42>>, 124), else: ""))
      end

    %{sender: sender, receiver: receiver, inputs: inputs, outputs: outputs, fee: 1}
  end

  def build(p, network \\ :mainnet),
    do: N.build_payment(unhex(p.sender.view_secret_hex), network, p.inputs, p.outputs, p.fee)

  def receive(raw, wallet, network \\ :mainnet),
    do:
      N.receive_payment(
        raw,
        unhex(wallet.spend_secret_hex),
        unhex(wallet.view_secret_hex),
        network
      )

  def replace(raw, offset, bytes) do
    size = byte_size(bytes)
    tail_offset = offset + size

    binary_part(raw, 0, offset) <>
      bytes <>
      binary_part(raw, tail_offset, byte_size(raw) - tail_offset)
  end

  def flip(raw, offset) do
    <<byte>> = binary_part(raw, offset, 1)
    replace(raw, offset, <<Bitwise.bxor(byte, 1)>>)
  end

  def wire_layout(raw) do
    <<1, _public::binary-size(32), ni::little-32, no::little-32, _fee::little-64, _::binary>> =
      raw

    {offset, outputs} =
      Enum.reduce(1..no, {49, []}, fn _, {offset, acc} ->
        <<len::little-32>> = binary_part(raw, offset + 200, 4)
        {offset + 204 + len, acc ++ [%{offset: offset, proof: offset + 204, proof_bytes: len}]}
      end)

    %{outputs: outputs, inputs: for(i <- 0..(ni - 1), do: offset + i * 2216)}
  end
end
