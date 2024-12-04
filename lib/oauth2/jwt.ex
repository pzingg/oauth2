defmodule OAuth2.Jwt do
  @moduledoc """
  Defines functions for DPoP creation and verification.
  """

  use Joken.Config

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

  `jwk` - A JWK with a private key. The `alg` of the JWK should be "ES256" (NIST "P-256")
    for use with Bluesky.
  `opts` - A keyword list. `:method` overrides the default "POST" method.

  Returns {:ok, token, claims} on success.
  """
  def dpop_create(%{"alg" => alg} = jwk_private, uri, nonce \\ nil, opts \\ []) do
    protected =
      %{
        "typ" => "dpop+jwt",
        "alg" => alg,
        "jwk" => Map.drop(jwk_private, ["alg", "d"])
      }

    extra_claims = %{
      "htm" => Keyword.get(opts, :method, "POST"),
      "htu" => uri
    }

    extra_claims =
      if is_binary(nonce) do
        Map.put(extra_claims, "nonce", nonce)
      else
        extra_claims
      end

    # Have to get the "protected" into the header of the JWS
    with %{jwk: jwk, jws: jws} = Joken.Signer.create(alg, jwk_private),
         jws = %JOSE.JWS{jws | fields: protected},
         {:ok, claims} <- __MODULE__.generate_claims(extra_claims),
         result <- JOSE.JWT.sign(jwk, jws, claims),
         {_, compacted_token} <- JOSE.JWS.compact(result) do
      {:ok, compacted_token, claims}
    else
      {:error, reason} -> {:error, reason}
      _ -> {:error, "what?"}
    end
  end
end
