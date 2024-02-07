// SPDX-FileCopyrightText: 2024 Demerzel Solutions Limited
// SPDX-License-Identifier: MIT

using System;
using FluentAssertions;
using NUnit.Framework;

namespace Nethermind.Crypto.Test;

using G1 = Bls.P1;
using G2 = Bls.P2;
using GT = Bls.PT;

[TestFixture]
public class BlsTests
{
    [Test]
    public void PairingTest1()
    {
        // e((12+34)*56*g1, 78*g2) == e(78*g1, 12*56*g2) * e(78*g1, 34*56*g2)
        GT q1 = new(G1.generator().mult((12 + 34) * 56), G2.generator().mult(78));
        GT q2 = new(G1.generator().mult(78), G2.generator().mult(12 * 56));
        GT q3 = new(G1.generator().mult(78), G2.generator().mult(34 * 56));
        q2.mul(q3);
        Assert.That(GT.finalverify(q1, q2));
    }

    [Test]
    public void PairingTest2()
    {
        GT q1 = new(G1.generator().mult(2), G2.generator());
        GT q2 = new(G1.generator(), G2.generator().mult(2));
        Assert.That(GT.finalverify(q1, q2));
    }
}