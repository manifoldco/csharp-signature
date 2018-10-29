# csharp-signature

Verify signed HTTP requests from Manifold

[Code of Conduct](./.github/CONDUCT.md) |
[Contribution Guidelines](./.github/CONTRIBUTING.md)

[![GitHub release](https://img.shields.io/github/tag/manifoldco/csharp-signature.svg?label=latest)](https://github.com/manifoldco/csharp-signature/releases)
[![Travis](https://img.shields.io/travis/manifoldco/csharp-signature/master.svg)](https://travis-ci.org/manifoldco/csharp-signature)
[![License](https://img.shields.io/badge/license-BSD-blue.svg)](./LICENSE.md)

## Usage

Install from nuget (todo) or download and build the solution from the releases tabs.

Verifying a request:

```c#
Verifier verifier = new Verifier(yourPublicKey);
try
{
    await verifier.VerifyAsync(httpRequestMessage);
    // The signature is valid
}
catch (Exception ex)
{
    // The signature is invalid
}
```