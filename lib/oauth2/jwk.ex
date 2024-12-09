defmodule OAuth2.JWK do
  @moduledoc """
  Defines functions for JWK creation.
  """

  require Logger

  @spec generate_key!(String.t()) :: JOSE.JWK.t()
  def generate_key!(curve)

  @supported_algs %{
    "ES256" => {:ec, :secp256r1},
    "ES256K" => {:ec, :secp256k1},
    "ES384" => {:ec, :secp384r1},
    "ES512" => {:ec, :secp512r1},
    "RS256" => {:rsa, 1024},
    "RS384" => {:rsa, 2048},
    "RS512" => {:rsa, 4096},
    "PS256" => {:rsa, 2048},
    "PS384" => {:rsa, 4096},
    "PS512" => {:rsa, 8192}
  }

  @doc """
  Returns a `JOSE.JWK` with "use" and "alg" fields.
  """
  def generate_key!(alg) do
    params = Map.get(@supported_algs, alg)

    if is_tuple(params) do
      JOSE.JWK.generate_key(params)
      |> add_signer(alg)
    else
      raise ArgumentError, "Unsupported algorithm '#{alg}'"
    end
  end

  def add_signer(jwk, alg) do
    %JOSE.JWK{jwk | fields: %{"use" => "sig", "alg" => alg}}
  end

  @doc """
  Returns a tuple of two Elixir maps, the first element containing
  the private key, with "use" and "alg" elements; the second containing
  the public key, without the "use" or "alg".
  """
  def to_maps(%JOSE.JWK{fields: %{"use" => "sig", "alg" => _}} = jwk) do
    private_map = JOSE.JWK.to_map(jwk) |> elem(1)
    public_map = JOSE.JWK.to_public_map(jwk) |> elem(1) |> Map.drop(["use", "alg"])
    {private_map, public_map}
  end

  @doc """
  Returns a JSON-encoded private JWK.
  """
  def to_json(%JOSE.JWK{fields: %{"use" => "sig", "alg" => _}} = jwk) do
    JOSE.JWK.to_map(jwk) |> elem(1) |> Jason.encode!()
  end

  @doc """
  Returns a `JOSE.JWK` struct from a JSON-encoded private JWK.
  """
  def from_json(json) do
    with {:ok, jwk_map} <- Jason.decode(json),
         %JOSE.JWK{} = jwk <- JOSE.JWK.from_map(jwk_map),
         true <- private_key_with_signer?(jwk) do
      {:ok, jwk}
    else
      false ->
        {:error, "Not a JWK for signing"}

      error ->
        error
    end
  end

  def private_key_with_signer?(%JOSE.JWK{fields: %{"use" => "sig", "alg" => alg}} = jwk)
      when is_binary(alg) do
    JOSE.JWK.to_public(jwk) != jwk
  end

  def private_key_with_signer?(_) do
    false
  end
end
