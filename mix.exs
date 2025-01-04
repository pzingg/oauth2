defmodule OAuth2.Mixfile do
  use Mix.Project

  @source_url "https://github.com/scrogson/oauth2"
  @version "2.2.0"

  def project do
    [
      app: :oauth2,
      name: "OAuth2",
      version: @version,
      elixir: "~> 1.17",
      deps: deps(),
      package: package(),
      description: description(),
      docs: docs(),
      elixirc_paths: elixirc_paths(Mix.env()),
      test_coverage: [tool: ExCoveralls],
      preferred_cli_env: [
        coveralls: :test,
        "coveralls.detail": :test,
        "coveralls.html": :test,
        docs: :dev
      ],
      dialyzer: dialyzer()
    ]
  end

  def application do
    [extra_applications: [:logger, :public_key]]
  end

  defp dialyzer do
    [
      plt_file: {:no_warn, "priv/plts/dialyzer.plt"}
    ]
  end

  defp deps do
    [
      {:req, "~> 0.5"},
      {:finch, "~> 0.19"},
      {:ssl_verify_fun, "~> 1.1.7", manager: :rebar3, override: true},
      {:jose, "~> 1.11"},

      # Test dependencies
      {:plug_cowboy, "~> 1.0", only: :test},

      # Tools
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.4", only: [:dev, :test], runtime: false},
      {:ex_doc, "~> 0.36", only: [:dev], runtime: false},
      {:excoveralls, "~> 0.18", only: [:test], runtime: false}
    ]
  end

  defp description do
    "An Elixir OAuth 2.0 Client Library"
  end

  defp docs do
    [
      extras: ["CHANGELOG.md", "README.md": [title: "Overview"]],
      main: "readme",
      source_ref: "v#{@version}",
      source_url: @source_url,
      skip_undefined_reference_warnings_on: ["CHANGELOG.md"],
      formatters: ["html"]
    ]
  end

  defp package do
    [
      files: ["lib", "mix.exs", "CHANGELOG.md", "README.md", "LICENSE"],
      maintainers: ["Sonny Scroggin"],
      licenses: ["MIT"],
      links: %{
        Changelog: "https://hexdocs.pm/oauth2/changelog.html",
        GitHub: @source_url
      }
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]
end
