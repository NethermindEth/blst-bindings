// SPDX-FileCopyrightText: 2024 Demerzel Solutions Limited
// SPDX-License-Identifier: MIT

using System;
using System.Numerics;
using NUnit.Framework;

namespace Nethermind.Crypto.Test;

using G1 = Bls.P1;
using G2 = Bls.P2;
using G1Affine = Bls.P1Affine;
using G2Affine = Bls.P2Affine;
using GT = Bls.PT;

public class BlsPointTests
{
    private const string G1GeneratorCompressed = "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb";
    private const string G2GeneratorCompressed = "93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8";

    [Test]
    public void GeneratorsMatchKnownEncodings()
    {
        Assert.Multiple(() =>
        {
            Assert.That(Convert.ToHexStringLower(G1.Generator().Compress()), Is.EqualTo(G1GeneratorCompressed));
            Assert.That(Convert.ToHexStringLower(G1Affine.Generator().Compress()), Is.EqualTo(G1GeneratorCompressed));
            Assert.That(Convert.ToHexStringLower(G2.Generator().Compress()), Is.EqualTo(G2GeneratorCompressed));
            Assert.That(Convert.ToHexStringLower(G2Affine.Generator().Compress()), Is.EqualTo(G2GeneratorCompressed));
        });
    }

    [Test]
    public void GeneratorRejectsShortBuffer()
    {
        Assert.Multiple(() =>
        {
            Assert.That(() => { _ = G1.Generator(new long[G1.Sz - 1]); }, Throws.ArgumentException);
            Assert.That(() => { _ = G1Affine.Generator(new long[G1Affine.Sz - 1]); }, Throws.ArgumentException);
            Assert.That(() => { _ = G2.Generator(new long[G2.Sz - 1]); }, Throws.ArgumentException);
            Assert.That(() => { _ = G2Affine.Generator(new long[G2Affine.Sz - 1]); }, Throws.ArgumentException);
            Assert.That(() => { _ = GT.One(new long[GT.Sz - 1]); }, Throws.ArgumentException);
        });
    }

    [Test]
    public void SerializeRoundtripG1()
    {
        G1 p = G1.Generator().Mult(12345);

        G1 fromSerialized = new(p.Serialize());
        Assert.That(fromSerialized.IsEqual(p));

        G1 fromCompressed = new(p.Compress());
        Assert.That(fromCompressed.IsEqual(p));

        G1Affine affine = p.ToAffine();
        Assert.That(affine.Serialize(), Is.EqualTo(p.Serialize()));
        Assert.That(affine.Compress(), Is.EqualTo(p.Compress()));
        Assert.That(new G1Affine(p.Serialize()).IsEqual(affine));
        Assert.That(new G1Affine(p.Compress()).IsEqual(affine));
    }

    [Test]
    public void SerializeRoundtripG2()
    {
        G2 p = G2.Generator().Mult(12345);

        G2 fromSerialized = new(p.Serialize());
        Assert.That(fromSerialized.IsEqual(p));

        G2 fromCompressed = new(p.Compress());
        Assert.That(fromCompressed.IsEqual(p));

        G2Affine affine = p.ToAffine();
        Assert.That(affine.Serialize(), Is.EqualTo(p.Serialize()));
        Assert.That(affine.Compress(), Is.EqualTo(p.Compress()));
        Assert.That(new G2Affine(p.Serialize()).IsEqual(affine));
        Assert.That(new G2Affine(p.Compress()).IsEqual(affine));
    }

    [Test]
    public void InfinityRoundtrip()
    {
        byte[] compressedInf = new byte[48];
        compressedInf[0] = 0xc0;

        G1Affine p = new(compressedInf);
        Assert.That(p.IsInf());
        Assert.That(p.Compress(), Is.EqualTo(compressedInf));

        byte[] serializedInf = p.Serialize();
        Assert.That(serializedInf[0], Is.EqualTo(0x40));
        Assert.That(serializedInf[1..], Has.All.EqualTo(0));
    }

    [TestCase("00", Bls.ERROR.BADENCODING, TestName = "AffineDecodeErrors(wrong length)")]
    [TestCase("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        Bls.ERROR.BADENCODING, TestName = "AffineDecodeErrors(non-canonical x)")]
    [TestCase("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002",
        Bls.ERROR.POINTNOTINGROUP, TestName = "AffineDecodeErrors(on curve outside subgroup)")]
    public void AffineDecodeErrors(string hex, Bls.ERROR expected)
    {
        byte[] encoded = Convert.FromHexString(hex);

        G1Affine p = new();
        Assert.That(p.TryDecode(encoded, out Bls.ERROR err), Is.False);
        Assert.That(err, Is.EqualTo(expected));
        Assert.That(
            () => { _ = new G1Affine(encoded); },
            Throws.TypeOf<Bls.BlsException>().With.Property("Error").EqualTo(expected));
    }

    [Test]
    public void UnvalidatedDecodeAllowsPointOutsideSubgroup()
    {
        // (0, 2) is on the curve but not in the subgroup; the Jacobian decode is unvalidated by design
        byte[] outsideSubgroup = new byte[96];
        outsideSubgroup[95] = 0x02;

        G1 p = new(outsideSubgroup);
        Assert.That(p.OnCurve());
        Assert.That(p.InGroup(), Is.False);
    }

    [Test]
    public void MapToRejectsWrongLength()
    {
        Assert.Multiple(() =>
        {
            Assert.That(() => { _ = new G1().MapTo(new byte[47]); }, Throws.ArgumentException);
            Assert.That(() => { _ = new G2().MapTo(new byte[47], new byte[48]); }, Throws.ArgumentException);
            Assert.That(() => { _ = new G2().MapTo(new byte[48], new byte[47]); }, Throws.ArgumentException);
        });
    }

    [Test]
    public void MultIdentities()
    {
        G1 g = G1.Generator();

        Assert.That(g.Dup().Mult(BigInteger.One).IsEqual(g));
        Assert.That(g.Dup().Mult(BigInteger.Zero).IsInf());
        Assert.That(g.Dup().Mult(2).IsEqual(g.Dup().Dbl()));
        Assert.That(g.Dup().Mult(3).IsEqual(g.Dup().Add(g).Add(g)));
        Assert.That(g.Dup().Mult(BigInteger.MinusOne).IsEqual(g.Dup().Neg()));
        Assert.That(g.Dup().Add(g.Dup().Neg()).IsInf());
        Assert.That(g.Dup().Cneg(false).IsEqual(g));
    }

    [Test]
    public void MultAgreesAcrossScalarRepresentations()
    {
        BigInteger k = BigInteger.Parse("31415926535897932384626433832795028841971693993751058209749445923");
        byte[] bendian = k.ToByteArray(isUnsigned: true, isBigEndian: true);

        Bls.Scalar scalar = new(bendian, Bls.ByteOrder.BigEndian);

        G1 viaBigInteger = G1.Generator().Mult(k);
        G1 viaScalar = G1.Generator().Mult(scalar);
        G1 viaBytes = G1.Generator().Mult(scalar.ToLendian());

        Assert.That(viaScalar.IsEqual(viaBigInteger));
        Assert.That(viaBytes.IsEqual(viaBigInteger));
    }

    [Test]
    public void ScalarArithmetic()
    {
        Bls.Scalar a = new(BigInteger.Parse("123456789123456789").ToByteArray(isUnsigned: true, isBigEndian: true), Bls.ByteOrder.BigEndian);
        Bls.Scalar b = new(BigInteger.Parse("987654321987654321").ToByteArray(isUnsigned: true, isBigEndian: true), Bls.ByteOrder.BigEndian);

        Assert.That((a + b - b).ToBendian(), Is.EqualTo(a.ToBendian()));
        Assert.That((a * b / b).ToBendian(), Is.EqualTo(a.ToBendian()));

        Bls.Scalar one = a / a;
        byte[] expectedOne = new byte[32];
        expectedOne[31] = 1;
        Assert.That(one.ToBendian(), Is.EqualTo(expectedOne));

        // multiplication in the scalar field matches multiplication on the curve
        Assert.That(G1.Generator().Mult(a * b).IsEqual(G1.Generator().Mult(a).Mult(b)));
    }

    [Test]
    public void ScalarReducesModOrder()
    {
        // the group order r reduces to zero
        byte[] r = Convert.FromHexString("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001");
        Bls.Scalar scalar = new(r, Bls.ByteOrder.BigEndian);
        Assert.That(scalar.ToBendian(), Has.All.EqualTo(0));
    }

    [TestCase("",
        "052926add2207b76ca4fa57a8734416c8dc95e24501772c814278700eed6d1e4e8cf62d9c09db0fac349612b759e79a1" +
        "08ba738453bfed09cb546dbb0783dbb3a5f1f566ed67bb6be0e8c67e2e81a4cc68ee29813bb7994998f3eae0c9c6a265")]
    [TestCase("abc",
        "03567bc5ef9c690c2ab2ecdf6a96ef1c139cc0b2f284dca0a9a7943388a49a3aee664ba5379a7655d3c68900be2f6903" +
        "0b9c15f3fe6e5cf4211f346271d7b01c8f3b28be689c8429c85b67af215533311f0b8dfaaa154fa6b88176c229f2885d")]
    public void HashToG1MatchesRfc9380TestVectors(string msg, string expected)
    {
        // RFC 9380 J.9.1 (BLS12381G1_XMD:SHA-256_SSWU_RO_)
        byte[] dst = "QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_"u8.ToArray();

        G1 p = new G1().HashTo(System.Text.Encoding.ASCII.GetBytes(msg), dst);
        Assert.That(Convert.ToHexStringLower(p.Serialize()), Is.EqualTo(expected));
    }

    [TestCase("",
        "05cb8437535e20ecffaef7752baddf98034139c38452458baeefab379ba13dff5bf5dd71b72418717047f5b0f37da03d" +
        "0141ebfbdca40eb85b87142e130ab689c673cf60f1a3e98d69335266f30d9b8d4ac44c1038e9dcdd5393faf5c41fb78a" +
        "12424ac32561493f3fe3c260708a12b7c620e7be00099a974e259ddc7d1f6395c3c811cdd19f1e8dbf3e9ecfdcbab8d6" +
        "0503921d7f6a12805e72940b963c0cf3471c7b2a524950ca195d11062ee75ec076daf2d4bc358c4b190c0c98064fdd92")]
    [TestCase("abc",
        "139cddbccdc5e91b9623efd38c49f81a6f83f175e80b06fc374de9eb4b41dfe4ca3a230ed250fbe3a2acf73a41177fd8" +
        "02c2d18e033b960562aae3cab37a27ce00d80ccd5ba4b7fe0e7a210245129dbec7780ccc7954725f4168aff2787776e6" +
        "00aa65dae3c8d732d10ecd2c50f8a1baf3001578f71c694e03866e9f3d49ac1e1ce70dd94a733534f106d4cec0eddd16" +
        "1787327b68159716a37440985269cf584bcb1e621d3a7202be6ea05c4cfe244aeb197642555a0645fb87bf7466b2ba48")]
    public void HashToG2MatchesRfc9380TestVectors(string msg, string expected)
    {
        // RFC 9380 J.10.1 (BLS12381G2_XMD:SHA-256_SSWU_RO_); serialized as x.c1 || x.c0 || y.c1 || y.c0
        byte[] dst = "QUUX-V01-CS02-with-BLS12381G2_XMD:SHA-256_SSWU_RO_"u8.ToArray();

        G2 p = new G2().HashTo(System.Text.Encoding.ASCII.GetBytes(msg), dst);
        Assert.That(Convert.ToHexStringLower(p.Serialize()), Is.EqualTo(expected));
    }

    [Test]
    public void MultiMultMatchesSingleMult()
    {
        const int npoints = 4;
        long[] rawPoints = new long[npoints * G1.Sz];
        byte[] rawScalars = new byte[npoints * 32];

        G1 expected = new();
        for (int i = 0; i < npoints; i++)
        {
            BigInteger k = BigInteger.Pow(31, i + 1);
            G1 p = G1.Generator(rawPoints.AsSpan(i * G1.Sz)).Mult(i + 2);
            expected.Add(p.Dup().Mult(k));
            k.TryWriteBytes(rawScalars.AsSpan(i * 32), out _, isUnsigned: true);
        }

        G1 res = new G1().MultiMult(rawPoints, rawScalars, npoints);
        Assert.That(res.IsEqual(expected));
    }

    [Test]
    public void MultiMultWithNoPointsIsInfinity()
    {
        G1 g1 = G1.Generator().MultiMult([], [], 0);
        Assert.That(g1.IsInf());

        G2 g2 = G2.Generator().MultiMult([], [], 0);
        Assert.That(g2.IsInf());
    }

    [Test]
    public void MultiMultRejectsBadArguments()
    {
        Assert.Multiple(() =>
        {
            Assert.That(() => { _ = new G1().MultiMult([], [], -1); }, Throws.TypeOf<ArgumentOutOfRangeException>());
            Assert.That(() => { _ = new G1().MultiMult(new long[G1.Sz], new byte[64], 2); }, Throws.ArgumentException);
            Assert.That(() => { _ = new G1().MultiMult(new long[2 * G1.Sz], new byte[32], 2); }, Throws.ArgumentException);
            Assert.That(() => { _ = new G2().MultiMult([], [], -1); }, Throws.TypeOf<ArgumentOutOfRangeException>());
            Assert.That(() => { _ = new G2().MultiMult(new long[G2.Sz], new byte[64], 2); }, Throws.ArgumentException);
            Assert.That(() => { _ = new G2().MultiMult(new long[2 * G2.Sz], new byte[32], 2); }, Throws.ArgumentException);
        });
    }

    [Test]
    public void GtOperations()
    {
        GT one = GT.One();
        Assert.That(one.IsOne());

        GT q = new(G1Affine.Generator(), G2Affine.Generator());
        // a raw Miller loop output only lands in the r-order subgroup after the final exponentiation
        Assert.That(q.InGroup(), Is.False);
        Assert.That(q.Dup().FinalExp().InGroup());
        Assert.That(q.Dup().Sqr().IsEqual(q.Dup().Mul(q)));
        Assert.That(q.Dup().Mul(one).IsEqual(q));
        Assert.That(q.ToBendian(), Has.Length.EqualTo(576));
    }

    [Test]
    public void PairingAsFp12MatchesMillerLoop()
    {
        Bls.Pairing ctx = new();
        ctx.RawAggregate(G2Affine.Generator(), G1Affine.Generator());
        ctx.Commit();

        GT direct = new(G2Affine.Generator(), G1Affine.Generator());
        Assert.That(ctx.AsFp12().IsEqual(direct));
    }

    [Test]
    public void PairingIsBilinear()
    {
        // e(a*g1, b*g2) == e(b*g1, a*g2)
        GT lhs = new(G1.Generator().Mult(1234).ToAffine(), G2.Generator().Mult(5678).ToAffine());
        GT rhs = new(G1.Generator().Mult(5678).ToAffine(), G2.Generator().Mult(1234).ToAffine());
        Assert.That(GT.FinalVerify(lhs, rhs));
    }
}
