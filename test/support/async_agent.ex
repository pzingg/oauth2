defmodule OAuth2.AsyncAgent do
  use Agent

  def start_link(name) do
    Agent.start_link(fn -> [] end, name: name)
  end

  def value(name) do
    Agent.get(name, & &1) |> Enum.reverse()
  end

  def to_string(name) do
    value(name) |> Enum.join("")
  end

  def append(name, data) do
    Agent.update(name, &[data | &1])
  end
end
