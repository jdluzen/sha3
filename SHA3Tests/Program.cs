extern alias SHA3;
extern alias SHA3Managed;
extern alias SHA3Portable;
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using PetaTest;

namespace SHA3Tests
{
    [TestFixture]
    class Program
    {
        static void Main(string[] args)
        {
            new PetaTest.Runner().Run(args);
        }

        string fileFormat = "{0}MsgKAT_{1}.txt.gz";
        string[] GetLines(bool isShort, int hashLen)
        {
            using (GZipStream g = new GZipStream(File.OpenRead(Path.Combine("..", Path.Combine("binaries", string.Format(fileFormat, isShort ? "Short" : "Long", hashLen)))), CompressionMode.Decompress))
            using (StreamReader reader = new StreamReader(g))
                return reader.ReadToEnd().Split('\r', '\n');
        }

        IEnumerable<Tuple<int, byte[], string>> GetDataAndHash(string[] lines)
        {
            for (int i = 0; i < lines.Length; i++)
            {
                if (!lines[i].StartsWith("#") && lines[i] != string.Empty)
                {
                    int len = int.Parse(lines[i].Split(' ')[2]);
                    if (len % 8 == 0)//only on byte ranges
                        yield return new Tuple<int, byte[], string>(len / 8, lines[i + 1].Split(' ')[2].FromHexString(), lines[i + 2].Split(' ')[2]);
                    i += 2;
                }
            }
        }

        IEnumerable<Func<byte[], int, byte[]>> GetImplementations(int hashLen)
        {
            return new Func<byte[], int, byte[]>[] { new SHA3::SHA3.SHA3(hashLen).Hash, new SHA3Managed::SHA3Managed.SHA3Managed(hashLen).Hash, new SHA3Portable::SHA3Managed.SHA3Managed(hashLen).Hash };
        }

        void RunTest(bool isShort, int hashLen)
        {
            string[] lines = GetLines(isShort, hashLen);
            foreach (Tuple<int, byte[], string> tup in GetDataAndHash(lines))
                foreach (Func<byte[], int, byte[]> func in GetImplementations(hashLen))
                {
                    string hash = BitConverter.ToString(func(tup.Item2, tup.Item1)).Replace("-", string.Empty);
                    if (hash != tup.Item3)
                        throw new Exception("Hash mismatch");
                    Console.WriteLine(tup.Item3);
                }
        }

        [Test]
        public void Short_224()
        {
            RunTest(true, 224);
        }

        [Test]
        public void Short_256()
        {
            RunTest(true, 256);
        }

        [Test]
        public void Short_384()
        {
            RunTest(true, 384);
        }

        [Test]
        public void Short_512()
        {
            RunTest(true, 512);
        }

        [Test]
        public void Long_224()
        {
            RunTest(false, 224);
        }

        [Test]
        public void Long_256()
        {
            RunTest(false, 256);
        }

        [Test]
        public void Long_384()
        {
            RunTest(false, 384);
        }

        [Test]
        public void Long_512()
        {
            RunTest(false, 512);
        }
    }
}
