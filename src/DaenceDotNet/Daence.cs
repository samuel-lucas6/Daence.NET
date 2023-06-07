using Geralt;
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace DaenceDotNet;

public static class Daence
{
    public const int KeySize = 64;
    public const int TagSize = 24;

    public static void Encrypt(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default)
    {
        Validation.EqualToSize(nameof(ciphertext), ciphertext.Length, plaintext.Length + TagSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);

        ReadOnlySpan<byte> k0 = key[..32];
        Span<byte> k1 = stackalloc byte[32], k2 = stackalloc byte[32];
        k1.Clear(); k2.Clear();
        key[32..48].CopyTo(k1);
        key[48..].CopyTo(k2);

        Span<byte> tag = ciphertext[..TagSize];
        CompressAuth(tag, plaintext, associatedData, k0, k1, k2);
        XChaCha20.Encrypt(ciphertext[TagSize..], plaintext, tag, k0);

        CryptographicOperations.ZeroMemory(k1);
        CryptographicOperations.ZeroMemory(k2);
    }

    public static void Decrypt(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default)
    {
        Validation.NotLessThanMin(nameof(ciphertext), ciphertext.Length, TagSize);
        Validation.EqualToSize(nameof(plaintext), plaintext.Length, ciphertext.Length - TagSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);

        ReadOnlySpan<byte> k0 = key[..32];
        Span<byte> k1 = stackalloc byte[32], k2 = stackalloc byte[32];
        k1.Clear(); k2.Clear();
        key[32..48].CopyTo(k1);
        key[48..].CopyTo(k2);

        ReadOnlySpan<byte> tag = ciphertext[..TagSize];
        XChaCha20.Decrypt(plaintext, ciphertext[TagSize..], tag, k0);

        Span<byte> computedTag = stackalloc byte[TagSize];
        CompressAuth(computedTag, plaintext, associatedData, k0, k1, k2);
        bool valid = ConstantTime.Equals(computedTag, tag);

        CryptographicOperations.ZeroMemory(k1);
        CryptographicOperations.ZeroMemory(k2);
        CryptographicOperations.ZeroMemory(computedTag);

        if (!valid) {
            CryptographicOperations.ZeroMemory(plaintext);
            throw new CryptographicException();
        }
    }

    private static void CompressAuth(Span<byte> tag, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> k0, ReadOnlySpan<byte> k1, ReadOnlySpan<byte> k2)
    {
        Span<byte> padding = stackalloc byte[16];
        padding.Clear();

        using var p1 = new IncrementalPoly1305(k1);
        using var p2 = new IncrementalPoly1305(k2);

        p1.Update(associatedData);
        p2.Update(associatedData);
        if (associatedData.Length % 16 != 0) {
            p1.Update(padding[(associatedData.Length % 16)..]);
            p2.Update(padding[(associatedData.Length % 16)..]);
        }

        p1.Update(plaintext);
        p2.Update(plaintext);
        if (plaintext.Length % 16 != 0) {
            p1.Update(padding[(plaintext.Length % 16)..]);
            p2.Update(padding[(plaintext.Length % 16)..]);
        }

        BinaryPrimitives.WriteUInt64LittleEndian(padding[..8], (ulong)associatedData.Length);
        BinaryPrimitives.WriteUInt64LittleEndian(padding[8..], (ulong)plaintext.Length);
        p1.Update(padding);
        p2.Update(padding);

        Span<byte> tag1 = stackalloc byte[16], tag2 = stackalloc byte[16];
        p1.Finalize(tag1);
        p2.Finalize(tag2);

        Span<byte> u0 = stackalloc byte[32], u1 = stackalloc byte[32];
        HChaCha20.DeriveKey(u0, k0, tag1);
        HChaCha20.DeriveKey(u1, u0, tag2);
        u1[..TagSize].CopyTo(tag);

        CryptographicOperations.ZeroMemory(tag1);
        CryptographicOperations.ZeroMemory(tag2);
        CryptographicOperations.ZeroMemory(u0);
        CryptographicOperations.ZeroMemory(u1);
    }
}
