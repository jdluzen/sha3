using Xunit;

namespace DZen.Security.Cryptography.Tests
{
    public enum TestType
    {
        Short,
        Long,
        ExtremelyLong
    }

    public class KeccakTests : Tests
    {

        [Fact]
        public void Short_224()
        {
            RunTest(TestType.Short, 224, true);
        }

        [Fact]
        public void Short_256()
        {
            RunTest(TestType.Short, 256, true);
        }

        [Fact]
        public void Short_384()
        {
            RunTest(TestType.Short, 384, true);
        }

        [Fact]
        public void Short_512()
        {
            RunTest(TestType.Short, 512, true);
        }

        [Fact]
        public void Long_224()
        {
            RunTest(TestType.Long, 224, true);
        }

        [Fact]
        public void Long_256()
        {
            RunTest(TestType.Long, 256, true);
        }

        [Fact]
        public void Long_384()
        {
            RunTest(TestType.Long, 384, true);
        }

        [Fact]
        public void Long_512()
        {
            RunTest(TestType.Long, 512, true);
        }

#if NETCOREAPP2_0_OR_GREATER
        [Fact]
        public void ExtremelyLong_224()
        {
            RunTest(TestType.ExtremelyLong, 224, true);
        }

        [Fact]
        public void ExtremelyLong_256()
        {
            RunTest(TestType.ExtremelyLong, 256, true);
        }

        [Fact]
        public void ExtremelyLong_384()
        {
            RunTest(TestType.ExtremelyLong, 384, true);
        }

        [Fact]
        public void ExtremelyLong_512()
        {
            RunTest(TestType.ExtremelyLong, 512, true);
        }
#endif
    }
}
