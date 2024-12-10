defmodule OAuth2.JwtTest do
  use ExUnit.Case, async: false

  test "creates a signed DPoP" do
    jwk = OAuth2.Jwt.generate_jwk_es256()
    uri = "https://bsky.social/oauth/par"
    nonce = "abcdefg"
    res = OAuth2.Jwt.dpop_create(jwk, uri, nonce)
    assert {:ok, token, _claims} = res
    assert String.starts_with?(token, "eyJhbGciOiJFUzI1NiIsImp3ay")
  end
end
