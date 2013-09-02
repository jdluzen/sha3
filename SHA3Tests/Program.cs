extern alias SHA3;
extern alias SHA3Managed;
extern alias SHA3Portable;
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using PetaTest;

namespace SHA3Tests
{
    enum TestType
    {
        Short,
        Long,
        ExtremelyLong
    }

    [TestFixture]
    class Program
    {
        static void Main(string[] args)
        {
            new PetaTest.Runner().Run(args);
        }

        static string fileFormat = "{0}MsgKAT_{1}.txt.gz";
        string[] GetLines(TestType type, int hashLen)
        {
            using (GZipStream g = new GZipStream(File.OpenRead(Path.Combine("..", Path.Combine("binaries", string.Format(fileFormat, type, hashLen)))), CompressionMode.Decompress))
            using (StreamReader reader = new StreamReader(g))
                return reader.ReadToEnd().Split('\r', '\n');
        }

        IEnumerable<Tuple<int, byte[], string>> GetDataAndHash(TestType type, string[] lines)
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
                                yield return new Tuple<int, byte[], string>(len / 8, lines[i + 1].Split(' ')[2].FromHexString(), lines[i + 2].Split(' ')[2]);
                            i += 2;
                        }
                    break;
                case TestType.ExtremelyLong:
                    for (int i = 0; i < lines.Length; i++)
                        if (!lines[i].StartsWith("#") && lines[i] != string.Empty)
                        {
                            yield return new Tuple<int, byte[], string>(int.Parse(lines[i].Split(' ')[2]), ASCIIEncoding.ASCII.GetBytes(lines[i + 1].Split(' ')[2]), lines[i + 2].Split(' ')[2]);
                            i += 2;
                        }
                    break;
            }
        }

        //System.Security.Cryptography.HashAlgorithm[] algos = new System.Security.Cryptography.HashAlgorithm[] { new SHA3Managed.SHA3.SHA3Managed(224) };
        //object[] algos = new object[] {  };

        /*IEnumerable<KeyValuePair<Func<byte[], int, int, byte[], int, int>, Func<byte[], int, int, byte[]>>> GetTransformBlocks(int hashLen)
        {
            yield return new KeyValuePair<Func<byte[], int, int, byte[], int, int>, Func<byte[], int, int, byte[]>>(algos[0].TransformBlock, algos[0].TransformFinalBlock);
            //return new Func<byte[], int, int, byte[]>[] { new SHA3::SHA3.SHA3Service(hashLen).Hash, new SHA3Managed::SHA3Managed.SHA3ManagedService(hashLen).Hash, new SHA3Portable::SHA3Managed.SHA3ManagedService(hashLen).Hash };
        }*/

        IEnumerable<object> GetImplementations(int hashLen)
        {
            yield return new SHA3::SHA3.SHA3Unmanaged(hashLen);
            yield return new SHA3Managed::SHA3.SHA3Managed(hashLen);
            yield return new SHA3Portable::SHA3.SHA3Managed(hashLen);
        }

        void RunTest(TestType type, int hashLen)
        {
            string[] lines = GetLines(type, hashLen);
            foreach (Tuple<int, byte[], string> tup in GetDataAndHash(type, lines))
            {
                foreach (object impl in GetImplementations(hashLen))
                {
                    Func<byte[], int, int, byte[], int, int> transformBlock = null;
                    Func<byte[], int, int, byte[]> transformFinalBlock = null;
                    Action init = null;
                    if (impl is HashAlgorithm)
                    {
                        transformBlock = (impl as HashAlgorithm).TransformBlock;
                        transformFinalBlock = (array, offset, count) =>
                            {
                                (impl as HashAlgorithm).TransformFinalBlock(array, offset, count);
                                return (impl as HashAlgorithm).Hash;
                            };
                        init = (impl as HashAlgorithm).Initialize;
                    }
                    else if (impl is SHA3Portable::SHA3.IHashAlgorithm)
                    {
                        transformBlock = (impl as SHA3Portable::SHA3.IHashAlgorithm).TransformBlock;
                        transformFinalBlock = (array, offset, count) =>
                            {
                                (impl as SHA3Portable::SHA3.IHashAlgorithm).TransformFinalBlock(array, offset, count);
                                return (impl as SHA3Portable::SHA3.IHashAlgorithm).Hash;
                            };
                        init = (impl as SHA3Portable::SHA3.IHashAlgorithm).Initialize;
                    }
                    int repeats = type == TestType.ExtremelyLong ? tup.Item1 : 1;
                    if (tup.Item1 > 0)//only on whole byte ranges
                        for (int r = 0; r < repeats; r++)
                            for (int i = 0; i < tup.Item2.Length; i++)//really stress the internal buffer
                                transformBlock(tup.Item2, i, 1, tup.Item2, i);
                    byte[] hash = transformFinalBlock(tup.Item2, 0, 0);
                    string shash = BitConverter.ToString(hash).Replace("-", string.Empty);
                    if (shash != tup.Item3)
                        throw new Exception("Hash mismatch");
                    Console.WriteLine(tup.Item3);

                    init();
                    if (tup.Item1 > 0)
                        for (int r = 0; r < repeats; r++)
                            transformBlock(tup.Item2, 0, tup.Item2.Length, tup.Item2, 0);//transform in one shot
                    hash = transformFinalBlock(tup.Item2, 0, 0);
                    shash = BitConverter.ToString(hash).Replace("-", string.Empty);
                    if (shash != tup.Item3)
                        throw new Exception("Hash mismatch");
                    Console.WriteLine(tup.Item3);
                }
            }
        }

        [Test]
        public void Short_224()
        {
            RunTest(TestType.Short, 224);
        }

        [Test]
        public void Short_256()
        {
            RunTest(TestType.Short, 256);
        }

        [Test]
        public void Short_384()
        {
            RunTest(TestType.Short, 384);
        }

        [Test]
        public void Short_512()
        {
            RunTest(TestType.Short, 512);
        }

        [Test]
        public void Long_224()
        {
            RunTest(TestType.Long, 224);
        }

        [Test]
        public void Long_256()
        {
            RunTest(TestType.Long, 256);
        }

        [Test]
        public void Long_384()
        {
            RunTest(TestType.Long, 384);
        }

        [Test]
        public void Long_512()
        {
            RunTest(TestType.Long, 512);
        }

        [Test]
        public void ExtremelyLong_224()
        {
            RunTest(TestType.ExtremelyLong, 224);
        }

        [Test]
        public void ExtremelyLong_256()
        {
            RunTest(TestType.ExtremelyLong, 256);
        }

        [Test]
        public void ExtremelyLong_384()
        {
            RunTest(TestType.ExtremelyLong, 384);
        }

        [Test]
        public void ExtremelyLong_512()
        {
            RunTest(TestType.ExtremelyLong, 512);
        }
    }
}
