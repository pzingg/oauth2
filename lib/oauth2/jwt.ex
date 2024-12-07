defmodule OAuth2.JWT do
  @moduledoc """
  Defines functions for JWK creation.
  """

  require Logger

  @type jwk_key() :: binary()
  @type jwk_map() :: %{required(jwk_key()) => binary()}

  @spec generate_private_jwk!(String.t()) :: jwk_map()
  def generate_private_jwk!(curve)

  def generate_private_jwk!("ES256") do
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

  def generate_private_jwk!(curve) do
    raise ArgumentError, "Curve #{curve} not implemented"
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

  # TODO Verify for types other than ES256
  def private_key?(%{"alg" => "ES256", "d" => d}) when is_binary(d), do: true

  def private_key?(%{"alg" => alg}) when is_binary(alg) do
    if alg != "ES256" do
      Logger.error("Unsupported JWK alg #{alg}")
    end

    false
  end

  def private_key?(_), do: false

  def public_key!(%{"alg" => "ES256"} = private_jwk) do
    Map.drop(private_jwk, ["d"])
  end

  def public_key!(jwk) do
    raise ArgumentError, "Unsupported JWK: #{inspect(jwk)}"
  end
end
