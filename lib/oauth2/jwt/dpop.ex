defmodule OAuth2.JWT.DPoP do
  @moduledoc """
  Defines functions for DPoP creation and verification.
  """

  use Joken.Config

  alias OAuth2.JWT

  @impl true
  @doc """
  We supply "iss" as part of our API. "aud" and "nbf" are not used.
  """
  def token_config do
    default_claims(skip: [:aud, :nbf, :iss])
  end

  @doc """
  Creates a DPoP token. If a nonce is supplied, it is added to the token's claims.

  - `private_jwk` - A JWK (Elixir map) with a private key. For Bluesky,
    the `"alg"` of the JWK should be "ES256" (NIST "P-256" curve).
  - `url` - the URL for the proof's `"htu"` claim.
  - `opts` - A keyword list:
    - `:nonce` (optional) - a value for the proof's `"nonce"` claim.
    - `:method` (optional, default `:post`) - `:get` or `:post`,
       will be uppercased as the proof's `"htm"` claim.
    - `:claims` (optional) - a map of additional claims to add
       with binary keys. Example: `%{"iss" => "https://bsky.social"}`

  Returns {:ok, {token, fields, claims}} on success.
  """
  @spec proof(JWT.jwk_map() | nil, String.t(), Keyword.t()) ::
          {:ok, binary(), map(), map()} | {:error, String.t()}
  def proof(private_jwk, url, opts \\ [])

  def proof(nil, _url, _opts) do
    {:error, "No JWK"}
  end

  def proof(private_jwk, url, opts) when is_map(private_jwk) do
    if JWT.private_key?(private_jwk) do
      # TODO Verify getting public key from private key types other than ES256
      alg = Map.fetch!(private_jwk, "alg")
      public_jwk = JWT.public_key!(private_jwk)

      fields =
        %{
          "typ" => "dpop+jwt",
          "alg" => alg,
          "jwk" => Map.drop(public_jwk, ["alg"])
        }

      method =
        opts
        |> Keyword.get(:method, :post)
        |> Atom.to_string()
        |> String.upcase(:ascii)

      extra_claims =
        opts
        |> Keyword.get(:claims, %{})
        |> Map.merge(%{
          "htm" => method,
          "htu" => url
        })

      nonce = Keyword.get(opts, :nonce)

      extra_claims =
        if is_binary(nonce) do
          Map.put(extra_claims, "nonce", nonce)
        else
          extra_claims
        end

      with %{jwk: jwk, jws: jws} = Joken.Signer.create(alg, private_jwk),
           jws = %JOSE.JWS{jws | fields: fields},
           {:ok, claims} <- generate_claims(extra_claims),
           result <- JOSE.JWT.sign(jwk, jws, claims),
           {_, compacted_token} <- JOSE.JWS.compact(result) do
        {:ok, {compacted_token, fields, claims}}
      else
        {:error, reason} -> {:error, reason}
        _ -> {:error, "JWK dpop error"}
      end
    else
      {:error, "A private JWK is required"}
    end
  end
end
