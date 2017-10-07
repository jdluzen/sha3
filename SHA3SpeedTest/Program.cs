extern alias SHA3;
extern alias SHA3Managed;
extern alias SHA3Portable;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace SHA3SpeedTest
{
    class Program
    {
        static void Main(string[] args)
        {
            byte[] data = new byte[1024 * 1024 * 10];
            Random rand = new Random();
            for (int i = -1; i < 10; i++)
            {
                int index = 0;
                foreach (object impl in new object[] { new SHA3::SHA3.SHA3Unmanaged(256), new SHA3Managed::SHA3.SHA3Managed(256), new SHA3Portable::SHA3.SHA3Managed(256), new SHA256Managed() })
                {
                    new SHA3.SHA3.SHA3Unmanaged(256).ComputeHash(UTF8Encoding.UTF8.GetBytes("Hello"));
                    rand.NextBytes(data);
                    //SHA256 s2 = SHA256.Create();
                    Func<byte[], int, int, byte[], int, int> transformBlock = null;
                    Func<byte[], int, int, byte[]> transformFinalBlock = null;
                    if (impl is HashAlgorithm)
                    {
                        transformBlock = (impl as HashAlgorithm).TransformBlock;
                        transformFinalBlock = (impl as HashAlgorithm).TransformFinalBlock;
                    }
                    else if (impl is SHA3Portable::SHA3.IHashAlgorithm)
                    {
                        transformBlock = (impl as SHA3Portable::SHA3.IHashAlgorithm).TransformBlock;
                        transformFinalBlock = (impl as SHA3Portable::SHA3.IHashAlgorithm).TransformFinalBlock;
                    }

                    DateTime begin = DateTime.UtcNow;
                    transformBlock(data, 0, data.Length, data, 0);
                    transformFinalBlock(data, 0, 0);
                    TimeSpan time = DateTime.UtcNow - begin;
                    switch (index++)
                    {
                        case 0:
                            Console.ForegroundColor = ConsoleColor.White;
                            break;
                        case 1:
                            Console.ForegroundColor = ConsoleColor.Green;
                            break;
                        case 2:
                            Console.ForegroundColor = ConsoleColor.Blue;
                            break;
                        case 3:
                            Console.ForegroundColor = ConsoleColor.Yellow;
                            break;

                    }
                    if (i >= 0)//ignore first run
                        Console.WriteLine("{0}mb in {1} on {2}, {3}mb/sec", data.Length / (1024 * 1024), time.TotalSeconds, IntPtr.Size == 4 ? "x86" : "amd64", (data.Length / (1024 * 1024)) / time.TotalSeconds);
                }
            }
        }
    }
}
