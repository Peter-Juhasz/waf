using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Firewall
{
    public static class HashAlgorithmPool
    {
        public static readonly HashAlgorithm Sha256 = SHA256.Create();
    }
}
