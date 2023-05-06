using System;
using System.Security.Cryptography;

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
            switch (hashName.ToLower().Replace("-", string.Empty))
            {
                case "sha3224":
                case "sha3224managed":
                    return new SHA3224Managed();
                case "sha3":
                case "sha3256":
                case "sha3256managed":
                    return new SHA3256Managed();
                case "sha3384":
                case "sha3384managed":
                    return new SHA3384Managed();
                case "sha3512":
                case "sha3512managed":
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
