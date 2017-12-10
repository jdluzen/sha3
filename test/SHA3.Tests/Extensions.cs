using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace DZen.Security.Cryptography.Tests
{
    public static class Extensions
    {
        public static byte[] FromHexString(this string hex)
        {
            if (hex.Length % 2 != 0)
                throw new Exception("hex.Length must be even");
            byte[] data = new byte[hex.Length / 2];
            int index = 0;
            for (int i = 0; i < hex.Length - 1; i += 2)
                data[index++] = Convert.ToByte(hex.Substring(i, 2), 16);
            return data;
        }
    }
}
