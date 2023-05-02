using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Text;
using Xunit;

namespace DZen.Security.Cryptography.Tests
{
    public abstract class Tests
    {
        protected static string fileFormat = "{0}MsgKAT_{1}{2}.txt.gz";
        protected string[] GetLines(TestType type, int hashLen, bool useKeccakPadding)
        {
            using (GZipStream g = new GZipStream(File.OpenRead(Path.Combine("..", "..", "..", "..", "..", "binaries", string.Format(fileFormat, type, useKeccakPadding ? "" : "SHA3-", hashLen))), CompressionMode.Decompress))
            using (StreamReader reader = new StreamReader(g))
                return reader.ReadToEnd().Split('\r', '\n');
        }

        protected IEnumerable<(int bytes, byte[] data, string hash)> GetDataAndHash(TestType type, string[] lines)
        {
            switch (type)
            {
                case TestType.Short:
                case TestType.Long:
                    for (int i = 0; i < lines.Length; i++)
                        if (!lines[i].StartsWith("#") && lines[i] != string.Empty)
                        {
                            int len = int.Parse(lines[i].Split(' ')[2]);
                            if (len % 8 == 0)//only on whole byte ranges
                                yield return (len / 8, lines[i + 1].Split(' ')[2].FromHexString(), lines[i + 2].Split(' ')[2]);
                            i += 2;
                        }
                    break;
#if NETCOREAPP2_0_OR_GREATER
                case TestType.ExtremelyLong:
                    for (int i = 0; i < lines.Length; i++)
                        if (!lines[i].StartsWith("#") && lines[i] != string.Empty)
                        {
                            yield return (int.Parse(lines[i].Split(' ')[2]), ASCIIEncoding.ASCII.GetBytes(lines[i + 1].Split(' ')[2]), lines[i + 2].Split(' ')[2]);
                            i += 2;
                        }
                    break;
#endif
            }
        }

        protected void RunTest(TestType type, int hashLen, bool useKeccakPadding)
        {
            string[] lines = GetLines(type, hashLen, useKeccakPadding);
            foreach ((int, byte[], string) tup in GetDataAndHash(type, lines))
            {
                SHA3 sha3 = SHA3.Create("sha3" + hashLen);
                sha3.UseKeccakPadding = useKeccakPadding;
                int repeats = type == TestType.ExtremelyLong ? tup.Item1 : 1;
                if (tup.Item1 > 0)//only on whole byte ranges
                {
                    byte[] hash;
                    string shash;
#if NETCOREAPP1_1_OR_GREATER
                    if (repeats == 1)
                    {
                        hash = sha3.ComputeHash(tup.Item2);
                        shash = Convert.ToHexString(hash);

                        Assert.Equal(tup.Item3, shash);
                    }
#endif
                    for (int r = 0; r < repeats; r++)
                        {
                            sha3.TransformBlock(tup.Item2, 0, tup.Item2.Length, tup.Item2, 0);
                        }
                        sha3.TransformFinalBlock(tup.Item2, 0, 0);
                        hash = sha3.Hash;

                    shash = Convert.ToHexString(hash);

                    Assert.Equal(tup.Item3, shash);
                }
            }
        }
    }
}