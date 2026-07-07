// SPDX-FileCopyrightText: 2024 Demerzel Solutions Limited
// SPDX-License-Identifier: MIT

using System;
using BenchmarkDotNet.Attributes;
using Nethermind.Crypto;

namespace Nethermind.Crypto.Bench;

using G1 = Bls.P1;
using G2 = Bls.P2;
using G1Affine = Bls.P1Affine;
using G2Affine = Bls.P2Affine;
using GT = Bls.PT;

public static class BenchmarkData
{
    public static readonly byte[] Dst = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"u8.ToArray();

    public static byte[] RandomScalar(Random rng)
    {
        byte[] scalar = new byte[32];
        rng.NextBytes(scalar);
        scalar[31] &= 0x1f; // keep the little-endian value below the group order
        return scalar;
    }
}

[MemoryDiagnoser]
public class KeyBenchmarks
{
    private readonly byte[] _ikm = new byte[32];
    private readonly byte[] _sk = new byte[32];
    private readonly long[] _pk = new long[G1.Sz];

    [GlobalSetup]
    public void Setup()
    {
        Random rng = new(42);
        rng.NextBytes(_ikm);
        new Bls.SecretKey(_sk).Keygen(_ikm);
    }

    [Benchmark]
    public long Keygen()
    {
        new Bls.SecretKey(_sk).Keygen(_ikm);
        return _sk[0];
    }

    [Benchmark]
    public long SkToPkG1()
    {
        new G1(_pk).FromSk(new Bls.SecretKey(_sk));
        return _pk[0];
    }
}

[MemoryDiagnoser]
public class SignatureBenchmarks
{
    private readonly byte[] _msg = new byte[32];
    private readonly byte[] _sk = new byte[32];
    private readonly long[] _pkAffine = new long[G1Affine.Sz];
    private readonly long[] _sigAffine = new long[G2Affine.Sz];
    private readonly long[] _hash = new long[G2.Sz];
    private readonly long[] _scratch = new long[G2.Sz];

    [GlobalSetup]
    public void Setup()
    {
        Random rng = new(42);
        rng.NextBytes(_msg);

        byte[] ikm = new byte[32];
        rng.NextBytes(ikm);
        Bls.SecretKey sk = new(_sk);
        sk.Keygen(ikm);

        new G1Affine(new G1(sk)).Point.CopyTo(_pkAffine);
        G2 sig = new G2(_hash).HashTo(_msg, BenchmarkData.Dst);
        new G2Affine(sig.Dup().SignWith(sk)).Point.CopyTo(_sigAffine);
    }

    [Benchmark]
    public long HashToG2()
    {
        new G2(_scratch).HashTo(_msg, BenchmarkData.Dst);
        return _scratch[0];
    }

    [Benchmark]
    public long SignPrehashed()
    {
        _hash.CopyTo(_scratch.AsSpan());
        new G2(_scratch).SignWith(new Bls.SecretKey(_sk));
        return _scratch[0];
    }

    [Benchmark]
    public bool Verify()
    {
        Bls.Pairing ctx = new(true, BenchmarkData.Dst);
        ctx.Aggregate(new G1Affine(_pkAffine), new G2Affine(_sigAffine), _msg);
        ctx.Commit();
        return ctx.FinalVerify();
    }
}

[MemoryDiagnoser]
public class G1Benchmarks
{
    private readonly byte[] _scalar = new byte[32];
    private readonly long[] _point = new long[G1.Sz];
    private readonly long[] _affine = new long[G1Affine.Sz];
    private readonly long[] _scratch = new long[G1.Sz];
    private byte[] _compressed = [];
    private byte[] _serialized = [];

    [GlobalSetup]
    public void Setup()
    {
        Random rng = new(42);
        BenchmarkData.RandomScalar(rng).CopyTo(_scalar.AsSpan());

        G1 p = G1.Generator(_point).Mult(_scalar);
        new G1Affine(p).Point.CopyTo(_affine);
        _compressed = p.Compress();
        _serialized = p.Serialize();
    }

    [Benchmark]
    public long Mult()
    {
        _point.CopyTo(_scratch.AsSpan());
        new G1(_scratch).Mult(_scalar);
        return _scratch[0];
    }

    [Benchmark]
    public long Add()
    {
        _point.CopyTo(_scratch.AsSpan());
        new G1(_scratch).Add(new G1Affine(_affine));
        return _scratch[0];
    }

    [Benchmark]
    public bool DecodeCompressedValidated()
        => new G1Affine(_scratch).TryDecode(_compressed, out _);

    [Benchmark]
    public bool DecodeUncompressedValidated()
        => new G1Affine(_scratch).TryDecode(_serialized, out _);

    [Benchmark]
    public bool DecodeUncompressedRaw()
        => new G1(_scratch).TryDecode(_serialized, out _);

    [Benchmark]
    public bool SubgroupCheck()
        => new G1(_point).InGroup();

    [Benchmark]
    public byte[] Compress()
        => new G1(_point).Compress();
}

[MemoryDiagnoser]
public class G2Benchmarks
{
    private readonly byte[] _scalar = new byte[32];
    private readonly long[] _point = new long[G2.Sz];
    private readonly long[] _affine = new long[G2Affine.Sz];
    private readonly long[] _scratch = new long[G2.Sz];
    private byte[] _compressed = [];
    private byte[] _serialized = [];

    [GlobalSetup]
    public void Setup()
    {
        Random rng = new(42);
        BenchmarkData.RandomScalar(rng).CopyTo(_scalar.AsSpan());

        G2 p = G2.Generator(_point).Mult(_scalar);
        new G2Affine(p).Point.CopyTo(_affine);
        _compressed = p.Compress();
        _serialized = p.Serialize();
    }

    [Benchmark]
    public long Mult()
    {
        _point.CopyTo(_scratch.AsSpan());
        new G2(_scratch).Mult(_scalar);
        return _scratch[0];
    }

    [Benchmark]
    public long Add()
    {
        _point.CopyTo(_scratch.AsSpan());
        new G2(_scratch).Add(new G2Affine(_affine));
        return _scratch[0];
    }

    [Benchmark]
    public bool DecodeCompressedValidated()
        => new G2Affine(_scratch).TryDecode(_compressed, out _);

    [Benchmark]
    public bool DecodeUncompressedValidated()
        => new G2Affine(_scratch).TryDecode(_serialized, out _);

    [Benchmark]
    public bool DecodeUncompressedRaw()
        => new G2(_scratch).TryDecode(_serialized, out _);

    [Benchmark]
    public bool SubgroupCheck()
        => new G2(_point).InGroup();

    [Benchmark]
    public byte[] Compress()
        => new G2(_point).Compress();
}

[MemoryDiagnoser]
public class PairingBenchmarks
{
    private readonly long[] _p = new long[G1Affine.Sz];
    private readonly long[] _q = new long[G2Affine.Sz];
    private readonly long[] _lines = new long[68 * 6 * 6];
    private readonly long[] _millerOut = new long[GT.Sz];
    private readonly long[] _scratch = new long[GT.Sz];

    [GlobalSetup]
    public void Setup()
    {
        Random rng = new(42);
        G1Affine p = new(G1.Generator().Mult(BenchmarkData.RandomScalar(rng)));
        G2Affine q = new(G2.Generator().Mult(BenchmarkData.RandomScalar(rng)));
        p.Point.CopyTo(_p);
        q.Point.CopyTo(_q);
        q.PrecomputeLines(_lines);
        new GT(_millerOut).MillerLoop(q, p);
    }

    [Benchmark]
    public long MillerLoop()
    {
        new GT(_scratch).MillerLoop(new G2Affine(_q), new G1Affine(_p));
        return _scratch[0];
    }

    [Benchmark]
    public long MillerLoopWithPrecomputedLines()
    {
        new GT(_scratch).MillerLoopLines(_lines, new G1Affine(_p));
        return _scratch[0];
    }

    [Benchmark]
    public long PrecomputeLines()
    {
        new G2Affine(_q).PrecomputeLines(_lines);
        return _lines[0];
    }

    [Benchmark]
    public long FinalExp()
    {
        _millerOut.CopyTo(_scratch.AsSpan());
        new GT(_scratch).FinalExp();
        return _scratch[0];
    }

    [Benchmark]
    public bool FinalVerify()
        => GT.FinalVerify(new GT(_millerOut), new GT(_millerOut));
}

[MemoryDiagnoser]
public class MsmBenchmarks
{
    [Params(16, 128, 512)]
    public int Npoints;

    private long[] _g1Points = [];
    private long[] _g2Points = [];
    private byte[] _scalars = [];
    private readonly long[] _g1Result = new long[G1.Sz];
    private readonly long[] _g2Result = new long[G2.Sz];

    [GlobalSetup]
    public void Setup()
    {
        Random rng = new(42);
        _g1Points = new long[Npoints * G1.Sz];
        _g2Points = new long[Npoints * G2.Sz];
        _scalars = new byte[Npoints * 32];

        for (int i = 0; i < Npoints; i++)
        {
            byte[] scalar = BenchmarkData.RandomScalar(rng);
            G1.Generator(_g1Points.AsSpan(i * G1.Sz)).Mult(scalar);
            G2.Generator(_g2Points.AsSpan(i * G2.Sz)).Mult(scalar);
            BenchmarkData.RandomScalar(rng).CopyTo(_scalars.AsSpan(i * 32));
        }
    }

    [Benchmark]
    public long G1MultiMult()
    {
        new G1(_g1Result).MultiMult(_g1Points, _scalars, Npoints);
        return _g1Result[0];
    }

    [Benchmark]
    public long G2MultiMult()
    {
        new G2(_g2Result).MultiMult(_g2Points, _scalars, Npoints);
        return _g2Result[0];
    }
}
