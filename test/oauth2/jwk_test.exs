defmodule OAuth2.JwkTest do
  use ExUnit.Case, async: false

  test "creates a signed DPoP" do
    jwk = OAuth2.JWK.generate_key!("ES256")
    uri = "https://bsky.social/oauth/par"
    res = OAuth2.DPoP.proof(jwk, uri, nonce: "abcdefg")
    assert {:ok, {token, header, claims}} = res
    assert String.starts_with?(token, "eyJhbGciOiJFUzI1NiIsImp3ay")
    assert header["typ"] == "dpop+jwt"
    assert header["alg"] == "ES256"
    assert get_in(header, ["jwk", "crv"]) == "P-256"
    assert claims["htm"] == "POST"
    assert claims["htu"] == uri
  end
end
