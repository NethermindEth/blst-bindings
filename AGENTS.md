# AGENTS instructions

C# bindings for blst. See [global.json](./global.json) and [src](./src/) directory for the project requirements and configuration.

## Project structure

- [src](./src/): The main codebase. The P/Invoke declarations mirror blst's [blst.h](https://github.com/supranational/blst/blob/master/bindings/blst.h) C API.
- [Nethermind.Crypto.Bls.Gen](./src/Nethermind.Crypto.Bls.Gen/): Generates `Bls.G1.cs` and `Bls.G2.cs` from [PointGroup.template](./src/Nethermind.Crypto.Bls.Gen/PointGroup.template); edit the template and regenerate instead of editing the generated files.
- [build-blst.yml](./.github/workflows/build-blst.yml): Builds blst for the specified version and opens a pull request with the resulting binaries.
- [test-publish.yml](./.github/workflows/test-publish.yml): Runs the tests and optionally publishes on NuGet.

## Coding guidelines

- Follow [.editorconfig](./.editorconfig).
- Do not assume; measure, research, ask if unsure.
- Keep comments short and to the point.
- Add tests for new code and bug fixes.
- Use conventional commits; keep scoped and imperative.
- Keep the native binaries under `src/Nethermind.Crypto.Bls/runtimes/` in sync with a single blst version; they are Git LFS objects updated only by [build-blst.yml](./.github/workflows/build-blst.yml), so do not edit or rebuild them locally.
- Keep the P/Invoke signatures and struct layouts in sync with the blst headers of the shipped binaries.
- Prefer the latest versions of GitHub Actions and runners.
- Update [THIRD-PARTY-NOTICES](./THIRD-PARTY-NOTICES) when introducing a dependency if needed.
- Keep [AGENTS.md](./AGENTS.md) in sync with the ongoing development.
