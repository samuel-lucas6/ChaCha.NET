/*
    ChaCha.NET: A .NET implementation of ChaCha8, ChaCha12, and ChaCha20.
    Copyright (c) 2022 Samuel Lucas
    
    Permission is hereby granted, free of charge, to any person obtaining a copy of
    this software and associated documentation files (the "Software"), to deal in
    the Software without restriction, including without limitation the rights to
    use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
    the Software, and to permit persons to whom the Software is furnished to do so,
    subject to the following conditions:
    
    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.
    
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
*/

using System.Security.Cryptography;

namespace ChaChaDotNet;

internal static class ChaCha
{
    internal const int KeySize = 32;
    internal const int NonceSize = 12;
    internal const int BlockSize = 64;
    private const int UIntSize = sizeof(uint);
    
    internal static uint Encrypt(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, uint counter = 0, int rounds = 20)
    {
        if (ciphertext.Length != plaintext.Length) { throw new ArgumentOutOfRangeException(nameof(ciphertext), ciphertext.Length, $"{nameof(ciphertext)} must be {plaintext.Length} bytes long."); }
        if (nonce.Length != NonceSize) { throw new ArgumentOutOfRangeException(nameof(nonce), nonce.Length, $"{nameof(nonce)} must be {NonceSize} bytes long."); }
        if (key.Length != KeySize) { throw new ArgumentOutOfRangeException(nameof(key), key.Length, $"{nameof(key)} must be {KeySize} bytes long."); }
        if (rounds != 20 && rounds != 12 && rounds != 8) { throw new ArgumentOutOfRangeException(nameof(rounds), rounds, $"{nameof(rounds)} must be 20, 12, or 8."); }
        long blockCount = (-1L + plaintext.Length + BlockSize) / BlockSize;
        if (counter + blockCount > uint.MaxValue) { throw new CryptographicException("Counter overflow prevented."); }
        
        const uint j0 = 0x61707865;
        const uint j1 = 0x3320646e;
        const uint j2 = 0x79622d32;
        const uint j3 = 0x6b206574;
        uint j4 = ReadUInt32LittleEndian(key[..4]);
        uint j5 = ReadUInt32LittleEndian(key[4..8]);
        uint j6 = ReadUInt32LittleEndian(key[8..12]);
        uint j7 = ReadUInt32LittleEndian(key[12..16]);
        uint j8 = ReadUInt32LittleEndian(key[16..20]);
        uint j9 = ReadUInt32LittleEndian(key[20..24]);
        uint j10 = ReadUInt32LittleEndian(key[24..28]);
        uint j11 = ReadUInt32LittleEndian(key[28..32]);
        uint j12 = counter;
        uint j13 = ReadUInt32LittleEndian(nonce[..4]);
        uint j14 = ReadUInt32LittleEndian(nonce[4..8]);
        uint j15 = ReadUInt32LittleEndian(nonce[8..12]);
        var x = new uint[16];
        
        int index = 0;
        int bytesRemaining = plaintext.Length;
        for (int i = 0; i < blockCount; i++) {
            x[0] = j0;
            x[1] = j1;
            x[2] = j2;
            x[3] = j3;
            x[4] = j4;
            x[5] = j5;
            x[6] = j6;
            x[7] = j7;
            x[8] = j8;
            x[9] = j9;
            x[10] = j10;
            x[11] = j11;
            x[12] = j12;
            x[13] = j13;
            x[14] = j14;
            x[15] = j15;
            
            for (int j = 0; j < rounds / 2; j++) {
                (x[0], x[4], x[8], x[12]) = QuarterRound(x[0], x[4], x[8], x[12]);
                (x[1], x[5], x[9], x[13]) = QuarterRound(x[1], x[5], x[9], x[13]);
                (x[2], x[6], x[10], x[14]) = QuarterRound(x[2], x[6], x[10], x[14]);
                (x[3], x[7], x[11], x[15]) = QuarterRound(x[3], x[7], x[11], x[15]);
                (x[0], x[5], x[10], x[15]) = QuarterRound(x[0], x[5], x[10], x[15]);
                (x[1], x[6], x[11], x[12]) = QuarterRound(x[1], x[6], x[11], x[12]);
                (x[2], x[7], x[8], x[13]) = QuarterRound(x[2], x[7], x[8], x[13]);
                (x[3], x[4], x[9], x[14]) = QuarterRound(x[3], x[4], x[9], x[14]);
            }
            
            x[0] += j0;
            x[1] += j1;
            x[2] += j2;
            x[3] += j3;
            x[4] += j4;
            x[5] += j5;
            x[6] += j6;
            x[7] += j7;
            x[8] += j8;
            x[9] += j9;
            x[10] += j10;
            x[11] += j11;
            x[12] += j12;
            x[13] += j13;
            x[14] += j14;
            x[15] += j15;
            
            if (bytesRemaining >= BlockSize) {
                for (int j = 0; j < x.Length; j++) {
                    x[j] ^= ReadUInt32LittleEndian(plaintext.Slice(index, UIntSize));
                    WriteUInt32LittleEndian(ciphertext.Slice(index, UIntSize), x[j]);
                    index += UIntSize;
                }
                bytesRemaining -= BlockSize;
            }
            else {
                int startIndex = 0;
                Span<byte> lastBlock = stackalloc byte[BlockSize];
                plaintext.Slice(plaintext.Length - bytesRemaining, bytesRemaining).CopyTo(lastBlock);
                for (int j = 0; j < (bytesRemaining + UIntSize - 1) / UIntSize; j++) {
                    x[j] ^= ReadUInt32LittleEndian(lastBlock.Slice(startIndex, UIntSize));
                    WriteUInt32LittleEndian(lastBlock.Slice(startIndex, UIntSize), x[j]);
                    startIndex += UIntSize;
                }
                for (int j = 0; j < bytesRemaining; j++) {
                    ciphertext[index++] = lastBlock[j];
                }
                CryptographicOperations.ZeroMemory(lastBlock);
            }
            j12++;
        }
        return j12;
    }
    
    private static uint ReadUInt32LittleEndian(ReadOnlySpan<byte> source)
    {
        return source[0] | (uint) source[1] << 8 | (uint) source[2] << 16 | (uint) source[3] << 24;
    }
    
    private static (uint a, uint b, uint c, uint d) QuarterRound(uint a, uint b, uint c, uint d)
    {
        a += b;
        d ^= a;
        d = RotateLeft(d, 16);
        c += d;
        b ^= c;
        b = RotateLeft(b, 12);
        a += b;
        d ^= a;
        d = RotateLeft(d, 8);
        c += d;
        b ^= c;
        b = RotateLeft(b, 7);
        return (a, b, c, d);
    }
    
    private static uint RotateLeft(uint a, int b)
    {
        return (a << b) ^ (a >> (32 - b));
    }
    
    private static void WriteUInt32LittleEndian(Span<byte> destination, uint value)
    {
        destination[0] = (byte) value;
        destination[1] = (byte) (value >> 8);
        destination[2] = (byte) (value >> 16);
        destination[3] = (byte) (value >> 24);
    }
}