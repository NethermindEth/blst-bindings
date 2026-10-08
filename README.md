# blst-bindings

[![Tests](https://github.com/nethermindeth/blst-bindings/actions/workflows/test-publish.yml/badge.svg)](https://github.com/nethermindeth/blst-bindings/actions/workflows/test-publish.yml)
[![Nethermind.Crypto.Bls](https://img.shields.io/nuget/v/Nethermind.Crypto.Bls)](https://www.nuget.org/packages/Nethermind.Crypto.Bls)

C# bindings for the [Supranational blst library](https://github.com/supranational/blst), supporting operations on the BLS12-381 curve and BLS signatures.

## Development

Run the tests:

```sh
dotnet test src -c release
```

Run the benchmarks (optionally filtered by class, e.g. `--filter '*MsmBenchmarks*'`):

```sh
dotnet run --project src/Nethermind.Crypto.Bls.Bench -c release
```

`Bls.G1.cs` and `Bls.G2.cs` are generated from a shared template. To change them, edit
`src/Nethermind.Crypto.Bls.Gen/PointGroup.template` and regenerate (CI verifies they match):

```sh
dotnet run --project src/Nethermind.Crypto.Bls.Gen
```

## License

This project is licensed under the [MIT](https://github.com/nethermindeth/blst-bindings/blob/main/LICENSE) license.

The package also ships prebuilt blst binaries, used under [Apache-2.0](https://github.com/supranational/blst/blob/master/LICENSE). See [THIRD-PARTY-NOTICES](https://github.com/nethermindeth/blst-bindings/blob/main/THIRD-PARTY-NOTICES) for the full text.
