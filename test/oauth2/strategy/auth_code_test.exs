defmodule OAuth2.Strategy.AuthCodeTest do
  use ExUnit.Case, async: true
  use Plug.Test

  import OAuth2.TestHelpers

  alias OAuth2.Client
  alias OAuth2.Strategy.AuthCode

  setup do
    client = build_client(strategy: AuthCode, site: test_server())
    {:ok, client: client}
  end

  test "authorize_url", %{client: client} do
    client = AuthCode.authorize_url(client, [])
    assert test_server() == client.site

    assert client.params["client_id"] == client.client_id
    assert client.params["redirect_uri"] == client.redirect_uri
    assert client.params["response_type"] == "code"
  end

  test "get_token", context do
    {client, stub_name} = test_client(context, :client)
    code = "abc1234"
    access_token = "access-token-1234"
    base64 = Base.encode64(client.client_id <> ":" <> client.client_secret)

    req_stub(stub_name, "POST", "/oauth/token", fn conn ->
      assert conn.method == "POST"
      assert conn.request_path == "/oauth/token"
      assert get_req_header(conn, "content-type") == ["application/x-www-form-urlencoded"]
      assert get_req_header(conn, "authorization") == ["Basic #{base64}"]

      # conn.body already parsed in req_stub
      body = conn.body_params
      assert is_map(body)

      assert body["grant_type"] == "authorization_code"
      assert body["code"] == code
      assert body["client_id"] == client.client_id
      assert body["redirect_uri"] == client.redirect_uri

      send_resp(conn, 200, ~s({"access_token":"#{access_token}"}))
    end)

    assert {:ok, %Client{token: token}} = Client.get_token(client, code: code)
    assert token.access_token == access_token
  end

  test "get_token throws and error if there is no 'code' param" do
    assert_raise OAuth2.Error, ~r/Missing required key/, fn ->
      AuthCode.get_token(build_client(), [], [])
    end
  end
end
