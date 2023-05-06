using Xunit;

namespace DZen.Security.Cryptography.Tests
{
    public class SHA3Tests : Tests
    {
        [Fact]
        public void Short_224()
        {
            RunTest(TestType.Short, 224, false);
        }

        [Fact]
        public void Short_256()
        {
            RunTest(TestType.Short, 256, false);
        }

        [Fact]
        public void Short_384()
        {
            RunTest(TestType.Short, 384, false);
        }

        [Fact]
        public void Short_512()
        {
            RunTest(TestType.Short, 512, false);
        }

        [Fact]
        public void CreateNamed()
        {
            foreach(string name in new string[]
            {
                "sha3",
                "sha3224managed",
                "sha3256managed",
                "sha3384managed",
                "sha3512managed",
                "sha3224",
                "sha3256",
                "sha3384",
                "sha3512",
            })
            {
                Assert.NotNull(SHA3.Create(name));
            }
        }
    }
}