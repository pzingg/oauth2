defmodule OAuth2.DPoP do
  @moduledoc """
  Defines functions for DPoP creation and verification.
  """

  @default_exp 2 * 60 * 60

  @doc """
  Creates a DPoP token. If a nonce is supplied, it is added to the token's claims.

  Returns {:ok, {token, header, claims}} on success.

  ## Arguments

  - `private_jwk` - A `JOSE.JWK` private key with `"use"` and `"alg"` elements.
  - `url` - the URL for the proof's `"htu"` claim.
  - `opts` - A keyword list of these options:
  - `:nonce` (default nil) - a value for the proof's `"nonce"` claim.
  - `:method` (default `:post`) - `:get` or `:post`,
      will be uppercased as the proof's `"htm"` claim.
  - `:expiration` (default 7200) - expiration period in seconds
  - `:current_time` (default now) - UNIX timestamp in seconds
  - `:claims` (default `%{}`) - a map of additional claims to add
      with binary keys. Example: `%{"iss" => "https://bsky.social"}`

  ## Notes

  If the `:claims` map has a `"nonce"` value, it will override the `:nonce` option.

  For Bluesky, the recommended `"alg"` of the JWK should be "ES256"
  (NIST "P-256" curve).
  """
  @spec proof(JOSE.JWK.t() | nil, String.t(), Keyword.t()) ::
          {:ok, {binary(), map(), map()}} | {:error, String.t()}
  def proof(private_jwk, url, opts \\ [])

  def proof(%JOSE.JWK{fields: %{"use" => "sig", "alg" => alg}} = private_jwk, url, opts) do
    claims = Keyword.get(opts, :claims, %{})

    claims =
      case Keyword.get(opts, :nonce) do
        nonce when is_binary(nonce) -> Map.put_new(claims, "nonce", nonce)
        _ -> claims
      end

    method =
      Keyword.get(opts, :method, :post)
      |> Atom.to_string()
      |> String.upcase(:ascii)

    exp = Keyword.get(opts, :expiration, @default_exp)
    time = Keyword.get(opts, :current_time, DateTime.utc_now() |> DateTime.to_unix())
    {private_map, public_map} = OAuth2.JWK.to_maps(private_jwk)

    header =
      %{
        "typ" => "dpop+jwt",
        "alg" => alg,
        "jwk" => public_map
      }

    default_claims =
      %{
        "iat" => time,
        "exp" => time + exp,
        "jti" => generate_jti(),
        "htm" => method,
        "htu" => url
      }

    claims = Map.merge(default_claims, claims)
    payload = Jason.encode!(claims)
    result = JOSE.JWS.sign(private_map, payload, header)
    token = JOSE.JWS.compact(result) |> elem(1)
    {:ok, {token, header, claims}}
  end

  def proof(%JOSE.JWK{}, _url, _opts) do
    {:error, "JWK is missing signer"}
  end

  def proof(_, _url, _opts) do
    {:error, "Not a JOSE.JWK"}
  end

  @doc """
  Default function for generating `jti` claims. This was inspired by the `Plug.RequestId` generation.
  It avoids using `strong_rand_bytes` as it is known to have some contention when running with many
  schedulers. Reused from `Joken` library.
  """
  @spec generate_jti() :: binary
  def generate_jti do
    binary = <<
      System.system_time(:nanosecond)::64,
      :erlang.phash2({node(), self()}, 16_777_216)::24,
      :erlang.unique_integer()::32
    >>

    Base.hex_encode32(binary, case: :lower)
  end
end
