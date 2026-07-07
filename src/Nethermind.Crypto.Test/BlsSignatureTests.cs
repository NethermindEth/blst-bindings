// SPDX-FileCopyrightText: 2024 Demerzel Solutions Limited
// SPDX-License-Identifier: MIT

using System;
using System.Numerics;
using NUnit.Framework;

namespace Nethermind.Crypto.Test;

using G1 = Bls.P1;
using G2 = Bls.P2;
using G1Affine = Bls.P1Affine;
using GT = Bls.PT;

public class BlsSignatureTests
{
    // ciphersuite for "minimal pubkey size" BLS signatures (pk in G1, sig in G2)
    private static readonly byte[] Dst = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"u8.ToArray();

    private static readonly byte[] Ikm = Convert.FromHexString("263dbd792f5b1be47ed85f8938c0f29586af0d3ac7b977f21c278fe1462040e3");

    [Test]
    public void KeygenIsDeterministic()
    {
        Bls.SecretKey a = new(Ikm, "");
        Bls.SecretKey b = new(Ikm, "");
        Assert.That(a.ToBendian(), Is.EqualTo(b.ToBendian()));
        Assert.That(a.ToBendian(), Has.Some.Not.EqualTo(0));
    }

    [Test]
    public void KeygenInfoIsUsed()
    {
        Bls.SecretKey a = new(Ikm, "");
        Bls.SecretKey b = new(Ikm, "info");
        Assert.That(a.ToBendian(), Is.Not.EqualTo(b.ToBendian()));
    }

    [Test]
    public void KeygenRejectsShortKeyMaterial()
    {
        // blst silently produces a zero key for short IKM, which must not be exposed
        byte[] shortIkm = new byte[31];
        Assert.Multiple(() =>
        {
            Assert.That(() => new Bls.SecretKey().Keygen(shortIkm), Throws.ArgumentException);
            Assert.That(() => new Bls.SecretKey().KeygenV3(shortIkm), Throws.ArgumentException);
            Assert.That(() => new Bls.SecretKey().KeygenV45(shortIkm, "salt"), Throws.ArgumentException);
            Assert.That(() => new Bls.SecretKey().KeygenV5(shortIkm, "salt"), Throws.ArgumentException);
            Assert.That(() => new Bls.SecretKey().DeriveMasterEip2333(shortIkm), Throws.ArgumentException);
        });
    }

    [Test]
    public void SecretKeyEncodingRoundtrip()
    {
        byte[] bendian = new byte[32];
        bendian[31] = 0x2a;
        bendian[0] = 0x2a;

        Bls.SecretKey sk = new(bendian, Bls.ByteOrder.BigEndian);
        Assert.That(sk.ToBendian(), Is.EqualTo(bendian));

        byte[] lendian = sk.ToLendian();
        Array.Reverse(lendian);
        Assert.That(lendian, Is.EqualTo(bendian));

        Bls.SecretKey fromLendian = new(sk.ToLendian(), Bls.ByteOrder.LittleEndian);
        Assert.That(fromLendian.ToBendian(), Is.EqualTo(bendian));
    }

    [TestCase("0000000000000000000000000000000000000000000000000000000000000000")] // zero
    [TestCase("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001")] // group order r
    [TestCase("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")] // > r
    public void SecretKeyRejectsOutOfRangeValues(string hex)
    {
        byte[] encoded = Convert.FromHexString(hex);
        Assert.That(
            () => { Bls.SecretKey sk = new(encoded, Bls.ByteOrder.BigEndian); },
            Throws.TypeOf<Bls.BlsException>().With.Property("Error").EqualTo(Bls.ERROR.BADENCODING));
    }

    [Test]
    public void SecretKeyAcceptsMaxValidValue()
    {
        // r - 1 is the largest valid secret key
        byte[] rMinusOne = Convert.FromHexString("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000");
        Bls.SecretKey sk = new(rMinusOne, Bls.ByteOrder.BigEndian);
        Assert.That(sk.ToBendian(), Is.EqualTo(rMinusOne));
    }

    [Test]
    public void Eip2333DeriveMasterAndChild()
    {
        // test case 0 from EIP-2333
        byte[] seed = Convert.FromHexString("c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04");
        byte[] expectedMaster = ToBendian32("6083874454709270928345386274498605044986640685124978867557563392430687146096");
        byte[] expectedChild = ToBendian32("20397789859736650942317412262472558107875392172444076792671091975210932703118");

        Bls.SecretKey master = new();
        master.DeriveMasterEip2333(seed);
        Assert.That(master.ToBendian(), Is.EqualTo(expectedMaster));

        Bls.SecretKey child = new(master, 0);
        Assert.That(child.ToBendian(), Is.EqualTo(expectedChild));
    }

    [Test]
    public void SignAndVerify()
    {
        byte[] msg = "message to sign"u8.ToArray();

        Bls.SecretKey sk = new(Ikm, "");
        G1 pk = new(sk);
        G2 sig = new G2().HashTo(msg, Dst).SignWith(sk);

        Assert.That(Verify(pk, sig, msg), Is.True);
    }

    [Test]
    public void VerifyRejectsWrongMessage()
    {
        byte[] msg = "message to sign"u8.ToArray();
        byte[] wrongMsg = "some other message"u8.ToArray();

        Bls.SecretKey sk = new(Ikm, "");
        G1 pk = new(sk);
        G2 sig = new G2().HashTo(msg, Dst).SignWith(sk);

        Assert.That(Verify(pk, sig, wrongMsg), Is.False);
    }

    [Test]
    public void VerifyRejectsWrongKey()
    {
        byte[] msg = "message to sign"u8.ToArray();

        Bls.SecretKey sk = new(Ikm, "");
        Bls.SecretKey wrongSk = new(Ikm, "different");
        G1 wrongPk = new(wrongSk);
        G2 sig = new G2().HashTo(msg, Dst).SignWith(sk);

        Assert.That(Verify(wrongPk, sig, msg), Is.False);
    }

    [Test]
    public void PairingVerifiesSignature()
    {
        byte[] msg = "message to sign"u8.ToArray();

        Bls.SecretKey sk = new(Ikm, "");
        G1 pk = new(sk);
        G2 sig = new G2().HashTo(msg, Dst).SignWith(sk);

        Bls.Pairing ctx = new(true, Dst);
        Bls.ERROR err = ctx.Aggregate(pk.ToAffine(), sig.ToAffine(), msg);
        Assert.That(err, Is.EqualTo(Bls.ERROR.SUCCESS));
        ctx.Commit();
        Assert.That(ctx.FinalVerify(), Is.True);
    }

    [Test]
    public void PairingRejectsInvalidSignature()
    {
        byte[] msg = "message to sign"u8.ToArray();

        Bls.SecretKey sk = new(Ikm, "");
        G1 pk = new(sk);
        G2 sig = new G2().HashTo("some other message"u8, Dst).SignWith(sk);

        Bls.Pairing ctx = new(true, Dst);
        Bls.ERROR err = ctx.Aggregate(pk.ToAffine(), sig.ToAffine(), msg);
        Assert.That(err, Is.EqualTo(Bls.ERROR.SUCCESS));
        ctx.Commit();
        Assert.That(ctx.FinalVerify(), Is.False);
    }

    [Test]
    public void PairingVerifiesMultipleSignatures()
    {
        Bls.Pairing ctx = new(true, Dst);

        for (int i = 0; i < 3; i++)
        {
            byte[] msg = [(byte)i, 0xab, 0xcd];
            Bls.SecretKey sk = new(Ikm, $"signer{i}");
            G1 pk = new(sk);
            G2 sig = new G2().HashTo(msg, Dst).SignWith(sk);

            Bls.ERROR err = ctx.Aggregate(pk.ToAffine(), sig.ToAffine(), msg);
            Assert.That(err, Is.EqualTo(Bls.ERROR.SUCCESS));
        }

        ctx.Commit();
        Assert.That(ctx.FinalVerify(), Is.True);
    }

    [Test]
    public void PairingRejectsInfinitePublicKey()
    {
        byte[] msg = "message to sign"u8.ToArray();

        Bls.SecretKey sk = new(Ikm, "");
        G2 sig = new G2().HashTo(msg, Dst).SignWith(sk);

        Bls.Pairing ctx = new(true, Dst);
        Bls.ERROR err = ctx.Aggregate(new G1Affine(), sig.ToAffine(), msg);
        Assert.That(err, Is.EqualTo(Bls.ERROR.PKISINFINITY));
    }

    [Test]
    public void AggregatedSignatureVerifies()
    {
        byte[] msg = "message to sign"u8.ToArray();

        // aggregate three signatures over the same message and verify against the sum of the keys
        G1 aggPk = new();
        G2 aggSig = new();
        for (int i = 0; i < 3; i++)
        {
            Bls.SecretKey sk = new(Ikm, $"signer{i}");
            aggPk.Aggregate(new G1(sk).ToAffine());
            aggSig.Aggregate(new G2().HashTo(msg, Dst).SignWith(sk).ToAffine());
        }

        Assert.That(Verify(aggPk, aggSig, msg), Is.True);
    }

    [Test]
    public void AggregateRejectsPointOutsideSubgroup()
    {
        // (0, 2) is on the G1 curve but not in the subgroup
        byte[] bytes = new byte[96];
        bytes[95] = 0x02;

        Assert.That(
            () =>
            {
                G1 point = new(bytes);
                new G1().Aggregate(point.ToAffine());
            },
            Throws.TypeOf<Bls.BlsException>().With.Property("Error").EqualTo(Bls.ERROR.POINTNOTINGROUP));
    }

    // e(pk, H(msg)) == e(g1, sig)
    private static bool Verify(G1 pk, G2 sig, ReadOnlySpan<byte> msg)
    {
        G2 hash = new G2().HashTo(msg, Dst);
        GT lhs = new(pk.ToAffine(), hash.ToAffine());
        GT rhs = new(G1Affine.Generator(), sig.ToAffine());
        return GT.FinalVerify(lhs, rhs);
    }

    private static byte[] ToBendian32(string dec)
    {
        byte[] bytes = BigInteger.Parse(dec).ToByteArray(isUnsigned: true, isBigEndian: true);
        byte[] padded = new byte[32];
        bytes.CopyTo(padded, 32 - bytes.Length);
        return padded;
    }
}
