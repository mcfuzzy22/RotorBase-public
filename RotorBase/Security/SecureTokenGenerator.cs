using System;
using System.Security.Cryptography;

namespace RotorBase.Security;

public static class SecureTokenGenerator
{
    public static string CreateToken(int bytes = 32)
    {
        if (bytes <= 0) throw new ArgumentOutOfRangeException(nameof(bytes));

        Span<byte> buffer = stackalloc byte[bytes];
        RandomNumberGenerator.Fill(buffer);
        return Convert.ToHexString(buffer);
    }
}
