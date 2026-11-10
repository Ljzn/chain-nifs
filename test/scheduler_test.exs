defmodule Parano1dNif.SchedulerTest do
  use ExUnit.Case, async: false
  alias Parano1dNif, as: API
  alias Parano1dNif.Fixtures, as: F

  @moduletag timeout: 600_000

  test "normal scheduler messages progress during proof and native gate rejects overlap" do
    assert :erlang.system_info(:schedulers_online) == 2,
           "run the harness with ERL_FLAGS='+S 2:2' mix precommit"

    supervisor = start_supervised!(Task.Supervisor)
    {:ok, unsigned} = API.build_transaction(F.request(9, 2))

    proof =
      Task.Supervisor.async_nolink(supervisor, fn ->
        API.authorize_transaction(unsigned.raw_transaction, F.secret())
      end)

    deadline = System.monotonic_time(:millisecond) + 30_000
    await_native_work(proof, deadline)
    assert Task.yield(proof, 0) == nil
    assert API.proof_status() == "busy"
    # A malformed but wrapper-sized payload would be rejected by decode if reached.
    # Busy must win for both entrypoints, including calls bypassing the wrapper.
    assert {:error, "busy"} = API.verify_transaction(<<0xA3, 128, 0>>)
    assert {:error, "busy"} = Parano1dNif.Native.verify_transaction(<<0xA3, 128, 0>>, 4)
    assert {:error, "busy"} = API.authorize_transaction(<<0xA3, 128, 0>>, F.secret())
    assert {:error, "busy"} = API.authorize_transaction(unsigned.raw_transaction, F.secret())

    parent = self()
    progress = Task.Supervisor.async_nolink(supervisor, fn -> ping(parent, 100) end)

    for expected <- 100..1//-1 do
      assert_receive {:progress, pid, ^expected}, 5_000
      send(pid, :continue)
    end

    assert Task.await(progress, 5_000) == :ok
    assert Task.yield(proof, 0) == nil
    assert API.proof_busy?()
    assert {:ok, signed} = Task.await(proof, 600_000)
    refute API.proof_busy?()
    assert API.proof_status() == "idle"

    assert {:error, "payment exceeds prototype page limit"} =
             API.verify_transaction(<<0xA3, 128, 0>>)

    assert {:ok, _} = API.verify_transaction(signed.raw_transaction)
  end

  defp await_native_work(task, deadline) do
    cond do
      API.proof_busy?() ->
        :ok

      System.monotonic_time(:millisecond) >= deadline ->
        flunk("native proof did not enter gate")

      true ->
        assert Task.yield(task, 0) == nil
        :erlang.yield()
        await_native_work(task, deadline)
    end
  end

  defp ping(_parent, 0), do: :ok

  defp ping(parent, remaining) do
    send(parent, {:progress, self(), remaining})

    receive do
      :continue -> ping(parent, remaining - 1)
    after
      5_000 -> raise "normal scheduler did not acknowledge progress"
    end
  end
end
