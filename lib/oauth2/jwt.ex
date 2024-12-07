defmodule OAuth2.Jwt do
  @moduledoc """
  Defines functions for DPoP creation and verification.
  """

  use Joken.Config

  require Logger

  @type jwk_key() :: binary()
  @type jwk_map() :: %{required(jwk_key()) => binary()}

  @spec generate_jwk_es256() :: jwk_map()
  def generate_jwk_es256() do
    # Generated with openssl ecparam -name prime256v1 -genkey -noout -out private-es256.key
    private_key = :jose_jwk_kty_ec.generate_key({:namedCurve, :secp256r1})

    {{:ECPrivateKey, _vsn, pkey_oct, {:namedCurve, _oid_tuple}, point_oct, _extra}, _fields} =
      private_key

    # Would like to do this, but don't know what "fields" argument should be
    # :jose_jwk_kty_ec.to_map(private_key, fields)

    # For secp256r1:
    #   pkey_oct has 32 bytes
    #   point_oct has 65 bytes, first byte is <<4>>
    {x_oct, y_oct} = get_x_y(point_oct)
    d = Base.url_encode64(pkey_oct, padding: false)
    x = Base.url_encode64(x_oct, padding: false)
    y = Base.url_encode64(y_oct, padding: false)

    %{
      "alg" => "ES256",
      "kty" => "EC",
      "crv" => "P-256",
      "x" => x,
      "y" => y,
      "d" => d
    }
  end

  defp get_x_y(<<_type::binary-size(1), x_oct::binary-size(32), y_oct::binary-size(32)>>) do
    {x_oct, y_oct}
  end

  defp get_x_y(<<_type::binary-size(1), x_oct::binary-size(48), y_oct::binary-size(48)>>) do
    {x_oct, y_oct}
  end

  defp get_x_y(<<_type::binary-size(1), x_oct::binary-size(66), y_oct::binary-size(66)>>) do
    {x_oct, y_oct}
  end

  @doc """
  Creates a DPoP token. If a nonce is supplied, it is added to the token's claims.

  - `jwk` - A JWK (Elixir map) with a private key. For Bluesky, the `alg` of the JWK
    should be "ES256" (NIST "P-256" curve).
  - `opts` - A keyword list:
    - `:nonce` (optional) - a nonce claim to be added
    - `:method` (optional, default `:post`) - `:get` or `:post`

  Returns {:ok, token, claims} on success.
  """

  @spec dpop_create(jwk_map() | nil, String.t(), Keyword.t()) ::
          {:ok, binary(), map()} | {:error, String.t()}
  def dpop_create(jwk_private, url, opts \\ [])

  def dpop_create(jwk_private, url, opts) do
    if private_key?(jwk_private) do
      # TODO Verify getting public key from private key types other than ES256
      alg = Map.fetch!(jwk_private, "alg")
      jwk_public = Map.drop(jwk_private, ["alg", "d"])

      protected =
        %{
          "typ" => "dpop+jwt",
          "alg" => alg,
          "jwk" => jwk_public
        }

      method = Keyword.get(opts, :method, :post)

      extra_claims = %{
        "htm" => Atom.to_string(method) |> String.upcase(:ascii),
        "htu" => url
      }

      nonce = Keyword.get(opts, :nonce)

      extra_claims =
        if is_binary(nonce) do
          Map.put(extra_claims, "nonce", nonce)
        else
          extra_claims
        end

      with %{jwk: jwk, jws: jws} = Joken.Signer.create(alg, jwk_private),
           jws = %JOSE.JWS{jws | fields: protected},
           {:ok, claims} <- __MODULE__.generate_claims(extra_claims),
           result <- JOSE.JWT.sign(jwk, jws, claims),
           {_, compacted_token} <- JOSE.JWS.compact(result) do
        {:ok, compacted_token, claims}
      else
        {:error, reason} -> {:error, reason}
        _ -> {:error, "JWK dpop error"}
      end
    else
      {:error, "A private JWK is required"}
    end
  end

  def dpop_create(_jwk_private, _url, _nonce, _opts) do
    {:error, "A private JWK is required"}
  end

  # TODO Verify for types other than ES256
  def private_key?(%{"alg" => "ES256", "d" => d}) when is_binary(d), do: true

  def private_key?(%{"alg" => alg}) when is_binary(alg) do
    if alg != "ES256" do
      Logger.error("Unsupported JWK alg #{alg}")
    end

    false
  end

  def private_key?(_), do: false
end
