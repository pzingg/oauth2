defmodule OAuth2.JwtTest do
  use ExUnit.Case, async: false

  test "cretes a signed DPoP" do
    jwk = OAuth2.Jwt.generate_jwk_es256()
    uri = "https://bsky.social/oauth/par"
    nonce = "abcdefg"
    res = OAuth2.Jwt.dpop_create(jwk, uri, nonce)
    assert {:ok, token, claims} = res
    IO.inspect(claims)
  end
end
