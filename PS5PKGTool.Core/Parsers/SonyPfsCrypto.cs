using System.Buffers;
using System.Buffers.Binary;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using PS5PKGTool.Core.Models;
using ProsperoPkgTool.Crypto;

namespace PS5PKGTool.Core.Parsers;

internal static class SonyPfsCrypto
{
    public const ulong SignedSectorFlag = 0x800000000000UL;

    public static byte[] DeriveEkpfs(string contentId, string passcode)
    {
        if (contentId.Length != 36) throw new ArgumentException("Content ID must contain 36 characters.", nameof(contentId));
        if (passcode.Length != 32) throw new ArgumentException("Passcode must contain 32 characters.", nameof(passcode));
        Span<byte> index = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(index, 1);
        byte[] paddedContentId = new byte[48];
        Encoding.ASCII.GetBytes(contentId).CopyTo(paddedContentId, 0);
        byte[] input = new byte[96];
        // Use the engine's managed SHA3-256: the BCL SHA3_256 throws PlatformNotSupportedException on
        // Windows builds without CNG SHA-3 support, and this runs at the start of every package build.
        Sha3.Sha3_256(index).CopyTo(input, 0);
        Sha3.Sha3_256(paddedContentId).CopyTo(input, 32);
        Encoding.ASCII.GetBytes(passcode).CopyTo(input, 64);
        return Sha3.Sha3_256(input);
    }

    public static SonyPfsCryptoContext DeriveContext(byte[] ekpfs, ReadOnlySpan<byte> seed,
        int blockSize, bool newCrypt)
    {
        byte[] baseKey = newCrypt ? HMACSHA256.HashData(ekpfs, seed) : ekpfs;
        byte[] material = new byte[4 + seed.Length];
        BinaryPrimitives.WriteUInt32LittleEndian(material, 1);
        seed.CopyTo(material.AsSpan(4));
        byte[] result = HMACSHA256.HashData(baseKey, material);
        return new SonyPfsCryptoContext(result[16..32], result[0..16], blockSize);
    }

    public static void DecryptBlock(Span<byte> block, SonyPfsCryptoContext context,
        ulong blockIndex, bool signedDomain)
        => TransformBlock(block, context, blockIndex, signedDomain, encrypt: false);

    public static void EncryptBlock(Span<byte> block, SonyPfsCryptoContext context,
        ulong blockIndex, bool signedDomain)
        => TransformBlock(block, context, blockIndex, signedDomain, encrypt: true);

    /// <summary>AES instances for a context, created once instead of per block. Instance members of
    /// <see cref="Aes"/> are not documented as thread-safe, so each use takes the lock.</summary>
    private sealed class Ciphers(byte[] dataKey, byte[] tweakKey)
    {
        public readonly Aes Data = CreateAes(dataKey);
        public readonly Aes Tweak = CreateAes(tweakKey);
    }

    private static readonly ConditionalWeakTable<SonyPfsCryptoContext, Ciphers> CipherCache = new();

    private static void TransformBlock(Span<byte> block, SonyPfsCryptoContext context,
        ulong blockIndex, bool signedDomain, bool encrypt)
    {
        if ((block.Length & 15) != 0) throw new InvalidDataException("An AES XTS block must be 16-byte aligned.");
        Ciphers ciphers = CipherCache.GetValue(context, static value => new Ciphers(value.DataKey, value.TweakKey));

        Span<byte> tweakInput = stackalloc byte[16];
        tweakInput.Clear();
        BinaryPrimitives.WriteUInt64LittleEndian(tweakInput,
            signedDomain ? blockIndex | SignedSectorFlag : blockIndex);
        Span<byte> tweak = stackalloc byte[16];
        lock (ciphers) ciphers.Tweak.EncryptEcb(tweakInput, tweak, PaddingMode.None);

        // Expand the whole tweak sequence up front (multiply by x in GF(2^128) per 16-byte unit), so
        // the data pass is XOR, one ECB call over the block, XOR, instead of one transform per unit.
        byte[] scratch = ArrayPool<byte>.Shared.Rent(block.Length * 2);
        try
        {
            Span<byte> tweaks = scratch.AsSpan(0, block.Length);
            Span<byte> buffer = scratch.AsSpan(block.Length, block.Length);
            ulong low = BinaryPrimitives.ReadUInt64LittleEndian(tweak);
            ulong high = BinaryPrimitives.ReadUInt64LittleEndian(tweak[8..]);
            for (int offset = 0; offset < tweaks.Length; offset += 16)
            {
                BinaryPrimitives.WriteUInt64LittleEndian(tweaks[offset..], low);
                BinaryPrimitives.WriteUInt64LittleEndian(tweaks[(offset + 8)..], high);
                ulong carry = high >> 63;
                high = (high << 1) | (low >> 63);
                low = (low << 1) ^ (carry * 0x87);
            }

            Xor(block, tweaks, buffer);
            lock (ciphers)
            {
                if (encrypt) ciphers.Data.EncryptEcb(buffer, block, PaddingMode.None);
                else ciphers.Data.DecryptEcb(buffer, block, PaddingMode.None);
            }
            Xor(block, tweaks, block);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(scratch);
        }
    }

    private static void Xor(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> destination)
    {
        int index = 0;
        if (Vector.IsHardwareAccelerated)
        {
            for (; index <= left.Length - Vector<byte>.Count; index += Vector<byte>.Count)
                (new Vector<byte>(left[index..]) ^ new Vector<byte>(right[index..])).CopyTo(destination[index..]);
        }
        for (; index < left.Length; index++) destination[index] = (byte)(left[index] ^ right[index]);
    }

    private static Aes CreateAes(byte[] key)
    {
        Aes aes = Aes.Create();
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;
        aes.KeySize = 128;
        aes.BlockSize = 128;
        aes.Key = key;
        return aes;
    }
}
