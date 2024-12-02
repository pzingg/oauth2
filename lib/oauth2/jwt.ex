defmodule OAuth2.Jwt do
  @moduledoc """
  Defines functions for DPoP creation and verification.
  """

  use Joken.Config

  def generate_jwk_es256() do
    # Generated with openssl ecparam -name prime256v1 -genkey -noout -out private-es256.key
    private_key = :jose_jwk_kty_ec.generate_key({:namedCurve, :secp256r1})
    {{:ECPrivateKey, _vsn, pkey_oct, {:namedCurve, _oid_tuple}, point_oct, _extra}, _fields} = private_key
    # pkey_oct has 32 bytes
    # point_oct has 65 bytes, first byte is <<4>>
    d = Base.url_encode64(pkey_oct, padding: false)
    <<_type::binary-size(1), x_oct::binary-size(32), y_oct::binary-size(32)>> = point_oct
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

  @doc """
  Creates a DPoP token. If a nonce is supplied, it is added to the
  token's claims.

  `alg` - The ES256 (NIST "P-256") cryptographic algorithm must be supported.

  Returns {:ok, token, claims} on success
  """
  def dpop_create(%{"alg" => alg} = jwk, uri, nonce \\ nil, opts \\ []) do
    method = Keyword.get(opts, :method, "POST")
    public_jwk = Map.drop(jwk, ["alg", "d"])
    extra_claims = %{
      "typ" => "dpop+jwt",
      "alg" => alg,
      "jwk" => public_jwk,
      "htm" => method,
      "htu" => uri
    }
    extra_claims =
      if is_binary(nonce) do
        Map.put(extra_claims, "nonce", nonce)
      else
        extra_claims
      end

    signer = Joken.Signer.create(alg, jwk)
    __MODULE__.generate_and_sign(extra_claims, signer)
  end
end
