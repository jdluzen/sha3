using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace DZen.Security.Cryptography
{
    public abstract class SHA3 : HashAlgorithm
    {
        #region Statics
        public static SHA3 Create()
        {
            return Create("SHA3-256");
        }

        public bool UseKeccakPadding { get; set; }

        public static SHA3 Create(string hashName)
        {
            switch (hashName.ToLower())
            {
                case "sha3-224":
                case "sha3224":
                    return new SHA3224Managed();
                case "sha3-256":
                case "sha3256":
                    return new SHA3256Managed();
                case "sha3-384":
                case "sha3384":
                    return new SHA3384Managed();
                case "sha3-512":
                case "sha3512":
                    return new SHA3512Managed();
                default:
                    return null;
            }
        }
        #endregion

        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (array == null)
                throw new ArgumentNullException("array");
            if (ibStart < 0)
                throw new ArgumentOutOfRangeException("ibStart");
            if (cbSize > array.Length)
                throw new ArgumentOutOfRangeException("cbSize");
            if (ibStart + cbSize > array.Length)
                throw new ArgumentOutOfRangeException("ibStart or cbSize");
        }
    }
}
