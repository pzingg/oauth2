defmodule OAuth2.Util do
  @moduledoc false

  @spec unix_now :: integer
  def unix_now do
    {mega, sec, _micro} = :os.timestamp()
    mega * 1_000_000 + sec
  end

  @spec content_type([{binary, binary}]) :: binary
  def content_type(headers) do
    case get_content_type(headers) do
      nil ->
        "application/json"

      content_type ->
        content_type
        |> remove_params()
        |> parse_content_type()
    end
  end

  defp remove_params(binary) do
    [content_type | _] = String.split(binary, ";")
    content_type
  end

  defp parse_content_type(content_type) do
    case String.split(content_type, "/") do
      [type, subtype] ->
        type <> "/" <> subtype

      _ ->
        raise OAuth2.Error, reason: "bad content-type: #{content_type}"
    end
  end

  defp get_content_type(headers) do
    case List.keyfind(headers, "content-type", 0) do
      {_, value} when is_binary(value) -> value
      {_, [value | _]} when is_binary(value) -> value
      _ -> nil
    end
  end
end
