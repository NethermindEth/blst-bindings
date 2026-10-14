// SPDX-FileCopyrightText: 2026 Demerzel Solutions Limited
// SPDX-License-Identifier: MIT

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Numerics;
using NUnit.Framework;

namespace Nethermind.Crypto.Test;

using G1 = Bls.P1;
using G2 = Bls.P2;
using G1Affine = Bls.P1Affine;
using G2Affine = Bls.P2Affine;
using GT = Bls.PT;

/// <summary>
/// Differential tests of the batched Pippenger MSM and batched Miller loop against references that
/// do not share their code path: single-point blst multiplication, single Miller loops, and a pure
/// BigInteger implementation of the curve arithmetic.
/// </summary>
public class BlsMsmDifferentialTests
{
    private static readonly BigInteger R = BigInteger.Parse("073eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", NumberStyles.HexNumber);
    private static readonly BigInteger P = BigInteger.Parse("01a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab", NumberStyles.HexNumber);
    private static readonly BigInteger Max256 = (BigInteger.One << 256) - 1;

    private static readonly BigInteger[] EdgeScalars = [0, 1, R - 1, R, R + 1, Max256, 2, R - 2, R * 2, Max256 - R];

    public static readonly int[] Sizes = [1, 2, 3, 7, 8, 9, 15, 16, 17, 31, 32, 33, 64, 65, 127, 128, 129, 256, 1024];

    public enum Shape
    {
        Random,
        EdgeScalars,
        DuplicatedPoints,
        WithNegations,
        AllSamePoint,
        AllSameEdgeScalar,
    }

    private static IEnumerable<TestCaseData> MsmCases()
    {
        foreach (int n in Sizes)
        {
            foreach (Shape shape in Enum.GetValues<Shape>())
            {
                yield return new TestCaseData(n, shape);
            }
        }
    }

    private static IEnumerable<TestCaseData> EdgeScalarCases()
    {
        foreach (BigInteger s in EdgeScalars)
        {
            yield return new TestCaseData(s.ToString("x"));
        }
    }

    /// <summary>Builds a deterministic MSM input: discrete logs of the points (base G) and the scalars.</summary>
    private static (BigInteger[] logs, BigInteger[] scalars) BuildInput(int n, Shape shape, int salt)
    {
        Random rng = new(n * 1009 + (int)shape * 31 + salt);
        BigInteger[] logs = new BigInteger[n];
        BigInteger[] scalars = new BigInteger[n];

        for (int i = 0; i < n; i++)
        {
            logs[i] = RandomBelow(rng, R - 1) + 1;
            scalars[i] = RandomBits(rng, 256);
        }

        switch (shape)
        {
            case Shape.EdgeScalars:
                for (int i = 0; i < n; i++)
                    scalars[i] = EdgeScalars[i % EdgeScalars.Length];
                break;
            case Shape.DuplicatedPoints:
                for (int i = 1; i < n; i += 2)
                    logs[i] = logs[rng.Next(i)];
                break;
            case Shape.WithNegations:
                // pair each point with its negation; for even n with equal scalars, these cancel to infinity
                for (int i = 1; i < n; i += 2)
                {
                    logs[i] = R - logs[i - 1];
                    if (rng.Next(2) == 0) scalars[i] = scalars[i - 1];
                }
                break;
            case Shape.AllSamePoint:
                for (int i = 1; i < n; i++)
                    logs[i] = logs[0];
                break;
            case Shape.AllSameEdgeScalar:
                for (int i = 0; i < n; i++)
                {
                    logs[i] = logs[0];
                    scalars[i] = EdgeScalars[(n + salt) % EdgeScalars.Length];
                }
                break;
        }

        return (logs, scalars);
    }

    private static BigInteger RandomBits(Random rng, int bits)
    {
        byte[] bytes = new byte[bits / 8 + 1];
        rng.NextBytes(bytes);
        bytes[^1] = 0;
        return new BigInteger(bytes, isUnsigned: true);
    }

    private static BigInteger RandomBelow(Random rng, BigInteger bound) => RandomBits(rng, 320) % bound;

    private static BigInteger Mod(BigInteger a, BigInteger m)
    {
        BigInteger r = a % m;
        return r.Sign < 0 ? r + m : r;
    }

    private static void WriteScalarLe(BigInteger s, Span<byte> dest)
    {
        dest[..32].Clear();
        Assert.That(s.TryWriteBytes(dest[..32], out _, isUnsigned: true, isBigEndian: false));
    }

    private static byte[] ScalarLe(BigInteger s)
    {
        byte[] b = new byte[32];
        WriteScalarLe(s, b);
        return b;
    }

    [TestCaseSource(nameof(EdgeScalarCases))]
    public void SingleMultMatchesPureReference(string scalarHex)
    {
        BigInteger s = BigInteger.Parse("0" + scalarHex, NumberStyles.HexNumber);
        BigInteger k = BigInteger.Parse("1234567890abcdef1234567890abcdef", NumberStyles.HexNumber);

        G1 g1 = G1.Generator().Mult(ScalarLe(k)).Mult(ScalarLe(s));
        G2 g2 = G2.Generator().Mult(ScalarLe(k)).Mult(ScalarLe(s));

        string g1Hex = Convert.ToHexStringLower(g1.Serialize());
        string g2Hex = Convert.ToHexStringLower(g2.Serialize());

        Assert.Multiple(() =>
        {
            Assert.That(g1Hex, Is.EqualTo(Convert.ToHexStringLower(PureCurve.G1.Mult(PureCurve.G1.Mult(PureCurve.G1.Generator, k), s).Serialize(isG2: false))));
            Assert.That(g2Hex, Is.EqualTo(Convert.ToHexStringLower(PureCurve.G2.Mult(PureCurve.G2.Mult(PureCurve.G2.Generator, k), s).Serialize(isG2: true))));
        });
    }

    [TestCaseSource(nameof(MsmCases))]
    public void G1MultiMultAffineMatchesNaive(int n, Shape shape)
    {
        (BigInteger[] logs, BigInteger[] scalars) = BuildInput(n, shape, 1);

        long[] affines = new long[n * G1Affine.Sz];
        byte[] rawScalars = new byte[n * 32];
        G1 naive = new();
        BigInteger combined = 0;

        for (int i = 0; i < n; i++)
        {
            G1 p = G1.Generator().Mult(ScalarLe(logs[i]));
            new G1Affine(p).Point.CopyTo(affines.AsSpan(i * G1Affine.Sz));
            WriteScalarLe(scalars[i], rawScalars.AsSpan(i * 32));
            naive.Add(p.Dup().Mult(ScalarLe(scalars[i])));
            combined += logs[i] * scalars[i];
        }

        G1 msm = new G1().MultiMultAffine(affines, rawScalars, n);
        G1 viaLog = G1.Generator().Mult(ScalarLe(Mod(combined, R)));

        string msmHex = Convert.ToHexStringLower(msm.Serialize());
        string naiveHex = Convert.ToHexStringLower(naive.Serialize());
        string viaLogHex = Convert.ToHexStringLower(viaLog.Serialize());

        Assert.Multiple(() =>
        {
            Assert.That(msmHex, Is.EqualTo(naiveHex), "MSM vs sum of single mults");
            Assert.That(msmHex, Is.EqualTo(viaLogHex), "MSM vs (sum s_i k_i) G");
        });

        if (n <= 33 || shape == Shape.EdgeScalars)
        {
            byte[] pure = PureCurve.G1.Mult(PureCurve.G1.Generator, Mod(combined, R)).Serialize(isG2: false);
            Assert.That(msmHex, Is.EqualTo(Convert.ToHexStringLower(pure)), "MSM vs pure reference");
        }
    }

    [TestCaseSource(nameof(MsmCases))]
    public void G2MultiMultAffineMatchesNaive(int n, Shape shape)
    {
        (BigInteger[] logs, BigInteger[] scalars) = BuildInput(n, shape, 2);

        long[] affines = new long[n * G2Affine.Sz];
        byte[] rawScalars = new byte[n * 32];
        G2 naive = new();
        BigInteger combined = 0;

        for (int i = 0; i < n; i++)
        {
            G2 p = G2.Generator().Mult(ScalarLe(logs[i]));
            new G2Affine(p).Point.CopyTo(affines.AsSpan(i * G2Affine.Sz));
            WriteScalarLe(scalars[i], rawScalars.AsSpan(i * 32));
            naive.Add(p.Dup().Mult(ScalarLe(scalars[i])));
            combined += logs[i] * scalars[i];
        }

        G2 msm = new G2().MultiMultAffine(affines, rawScalars, n);
        G2 viaLog = G2.Generator().Mult(ScalarLe(Mod(combined, R)));

        string msmHex = Convert.ToHexStringLower(msm.Serialize());
        string naiveHex = Convert.ToHexStringLower(naive.Serialize());
        string viaLogHex = Convert.ToHexStringLower(viaLog.Serialize());

        Assert.Multiple(() =>
        {
            Assert.That(msmHex, Is.EqualTo(naiveHex), "MSM vs sum of single mults");
            Assert.That(msmHex, Is.EqualTo(viaLogHex), "MSM vs (sum s_i k_i) G");
        });

        if (n <= 33 || shape == Shape.EdgeScalars)
        {
            byte[] pure = PureCurve.G2.Mult(PureCurve.G2.Generator, Mod(combined, R)).Serialize(isG2: true);
            Assert.That(msmHex, Is.EqualTo(Convert.ToHexStringLower(pure)), "MSM vs pure reference");
        }
    }

    [Test]
    public void MultiMultAffineRandomSizes([Values(1, 2, 3, 4)] int seed)
    {
        Random rng = new(seed);
        for (int iter = 0; iter < 50; iter++)
        {
            int n = rng.Next(2, 300);
            Shape shape = (Shape)rng.Next(Enum.GetValues<Shape>().Length);
            (BigInteger[] logs, BigInteger[] scalars) = BuildInput(n, shape, seed * 1000 + iter);

            long[] g1Affines = new long[n * G1Affine.Sz];
            long[] g2Affines = new long[n * G2Affine.Sz];
            byte[] rawScalars = new byte[n * 32];
            BigInteger combined = 0;

            for (int i = 0; i < n; i++)
            {
                byte[] log = ScalarLe(logs[i]);
                new G1Affine(G1.Generator().Mult(log)).Point.CopyTo(g1Affines.AsSpan(i * G1Affine.Sz));
                new G2Affine(G2.Generator().Mult(log)).Point.CopyTo(g2Affines.AsSpan(i * G2Affine.Sz));
                WriteScalarLe(scalars[i], rawScalars.AsSpan(i * 32));
                combined += logs[i] * scalars[i];
            }

            byte[] c = ScalarLe(Mod(combined, R));
            string g1 = Convert.ToHexStringLower(new G1().MultiMultAffine(g1Affines, rawScalars, n).Serialize());
            string g2 = Convert.ToHexStringLower(new G2().MultiMultAffine(g2Affines, rawScalars, n).Serialize());
            string g1Expected = Convert.ToHexStringLower(G1.Generator().Mult(c).Serialize());
            string g2Expected = Convert.ToHexStringLower(G2.Generator().Mult(c).Serialize());

            Assert.That(g1, Is.EqualTo(g1Expected), $"G1 n={n} shape={shape}");
            Assert.That(g2, Is.EqualTo(g2Expected), $"G2 n={n} shape={shape}");
        }
    }

    [TestCaseSource(nameof(MsmCases))]
    public void MillerLoopNMatchesSingleLoops(int n, Shape shape)
    {
        (BigInteger[] a, BigInteger[] b) = BuildInput(n, shape, 3);

        long[] qAffines = new long[n * G2Affine.Sz];
        long[] pAffines = new long[n * G1Affine.Sz];
        GT product = GT.One();
        BigInteger combined = 0;

        for (int i = 0; i < n; i++)
        {
            // keep both points away from infinity: the caller filters those out
            BigInteger bi = Mod(b[i], R);
            if (bi.IsZero) bi = 1;

            G1Affine p = new(G1.Generator().Mult(ScalarLe(a[i])));
            G2Affine q = new(G2.Generator().Mult(ScalarLe(bi)));
            p.Point.CopyTo(pAffines.AsSpan(i * G1Affine.Sz));
            q.Point.CopyTo(qAffines.AsSpan(i * G2Affine.Sz));
            product.Mul(new GT(q, p));
            combined += a[i] * bi;
        }

        GT batched = new(new long[GT.Sz]);
        batched.MillerLoopN(qAffines, pAffines, n);
        bool rawEqual = batched.IsEqual(product);

        batched.FinalExp();
        product.FinalExp();

        BigInteger c = Mod(combined, R);
        GT expected = c.IsZero
            ? GT.One()
            : new GT(new G2Affine(G2.Generator()), new G1Affine(G1.Generator().Mult(ScalarLe(c)))).FinalExp();

        bool finalEqual = batched.IsEqual(product);
        bool expectedEqual = batched.IsEqual(expected);
        bool isOne = batched.IsOne();

        Assert.Multiple(() =>
        {
            Assert.That(rawEqual, "batched Miller loop vs product of single loops");
            Assert.That(finalEqual, "after final exponentiation");
            Assert.That(expectedEqual, "vs e(cG1, G2) with c = sum a_i b_i");
            Assert.That(isOne, Is.EqualTo(c.IsZero));
        });
    }

    /// <summary>
    /// Minimal Jacobian-coordinate arithmetic on y^2 = x^3 + b over Fp2 (G1 lives in the c1 = 0 subfield),
    /// written independently of blst to serve as a reference.
    /// </summary>
    private static class PureCurve
    {
        public readonly record struct Fp2(BigInteger A, BigInteger B)
        {
            public static readonly Fp2 Zero = new(0, 0);
            public static readonly Fp2 One = new(1, 0);
            public bool IsZero => A.IsZero && B.IsZero;
            public static Fp2 operator +(Fp2 x, Fp2 y) => new(Mod(x.A + y.A, P), Mod(x.B + y.B, P));
            public static Fp2 operator -(Fp2 x, Fp2 y) => new(Mod(x.A - y.A, P), Mod(x.B - y.B, P));
            public static Fp2 operator *(Fp2 x, Fp2 y) => new(Mod(x.A * y.A - x.B * y.B, P), Mod(x.A * y.B + x.B * y.A, P));
            public static Fp2 operator *(int k, Fp2 x) => new(Mod(k * x.A, P), Mod(k * x.B, P));

            public Fp2 Inverse()
            {
                BigInteger norm = Mod(A * A + B * B, P);
                BigInteger inv = BigInteger.ModPow(norm, P - 2, P);
                return new(Mod(A * inv, P), Mod(-B * inv, P));
            }
        }

        public readonly record struct Point(Fp2 X, Fp2 Y, Fp2 Z)
        {
            public bool IsInf => Z.IsZero;

            public byte[] Serialize(bool isG2)
            {
                int len = isG2 ? 192 : 96;
                byte[] res = new byte[len];
                if (IsInf)
                {
                    res[0] = 0x40;
                    return res;
                }

                Fp2 zi = Z.Inverse();
                Fp2 zi2 = zi * zi;
                Fp2 x = X * zi2;
                Fp2 y = Y * zi2 * zi;

                if (isG2)
                {
                    Write(x.B, res.AsSpan(0, 48));
                    Write(x.A, res.AsSpan(48, 48));
                    Write(y.B, res.AsSpan(96, 48));
                    Write(y.A, res.AsSpan(144, 48));
                }
                else
                {
                    Write(x.A, res.AsSpan(0, 48));
                    Write(y.A, res.AsSpan(48, 48));
                }

                return res;
            }

            private static void Write(BigInteger v, Span<byte> dest)
            {
                int count = v.GetByteCount(isUnsigned: true);
                v.TryWriteBytes(dest[(48 - count)..], out _, isUnsigned: true, isBigEndian: true);
            }
        }

        public sealed class Group(Point generator)
        {
            public Point Generator { get; } = generator;
            private static readonly Point Infinity = new(Fp2.One, Fp2.One, Fp2.Zero);

            private static Point Double(Point p)
            {
                if (p.IsInf || p.Y.IsZero) return Infinity;
                Fp2 a = p.X * p.X;
                Fp2 b = p.Y * p.Y;
                Fp2 c = b * b;
                Fp2 t = p.X + b;
                Fp2 d = 2 * (t * t - a - c);
                Fp2 e = 3 * a;
                Fp2 f = e * e;
                Fp2 x3 = f - 2 * d;
                Fp2 y3 = e * (d - x3) - 8 * c;
                Fp2 z3 = 2 * (p.Y * p.Z);
                return new(x3, y3, z3);
            }

            private static Point Add(Point p, Point q)
            {
                if (p.IsInf) return q;
                if (q.IsInf) return p;
                Fp2 z1z1 = p.Z * p.Z;
                Fp2 z2z2 = q.Z * q.Z;
                Fp2 u1 = p.X * z2z2;
                Fp2 u2 = q.X * z1z1;
                Fp2 s1 = p.Y * q.Z * z2z2;
                Fp2 s2 = q.Y * p.Z * z1z1;
                Fp2 h = u2 - u1;
                Fp2 rr = s2 - s1;
                if (h.IsZero) return rr.IsZero ? Double(p) : Infinity;
                Fp2 hh = h * h;
                Fp2 hhh = h * hh;
                Fp2 v = u1 * hh;
                Fp2 x3 = rr * rr - hhh - 2 * v;
                Fp2 y3 = rr * (v - x3) - s1 * hhh;
                Fp2 z3 = p.Z * q.Z * h;
                return new(x3, y3, z3);
            }

            public Point Mult(Point p, BigInteger k)
            {
                Point acc = Infinity;
                for (int i = (int)k.GetBitLength() - 1; i >= 0; i--)
                {
                    acc = Double(acc);
                    if (!(k >> i).IsEven) acc = Add(acc, p);
                }
                return acc;
            }
        }

        private static BigInteger Read(ReadOnlySpan<byte> be) => new(be, isUnsigned: true, isBigEndian: true);

        public static readonly Group G1 = CreateG1();
        public static readonly Group G2 = CreateG2();

        private static Group CreateG1()
        {
            byte[] s = Bls.P1.Generator().Serialize();
            return new(new Point(new Fp2(Read(s.AsSpan(0, 48)), 0), new Fp2(Read(s.AsSpan(48, 48)), 0), Fp2.One));
        }

        private static Group CreateG2()
        {
            byte[] s = Bls.P2.Generator().Serialize();
            return new(new Point(
                new Fp2(Read(s.AsSpan(48, 48)), Read(s.AsSpan(0, 48))),
                new Fp2(Read(s.AsSpan(144, 48)), Read(s.AsSpan(96, 48))),
                Fp2.One));
        }
    }
}
