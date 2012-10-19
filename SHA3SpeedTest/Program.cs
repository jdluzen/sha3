extern alias SHA3;
extern alias SHA3Managed;
extern alias SHA3Portable;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SHA3SpeedTest
{
    class Program
    {
        static void Main(string[] args)
        {
            byte[] data = new byte[1024 * 1024 * 10];
            Random rand = new Random();
            for (int i = 0; i < 10; i++)
            {
                int index = 0;
                foreach (var func in new Func<byte[], byte[]>[] { new SHA3::SHA3.SHA3(256).Hash, new SHA3Managed::SHA3Managed.SHA3Managed(256).Hash, new SHA3Portable::SHA3Managed.SHA3Managed(256).Hash })
                {
                    rand.NextBytes(data);
                    //SHA256 s2 = SHA256.Create();
                    DateTime begin = DateTime.UtcNow;
                    byte[] hash = func(data);
                    //byte[] hash = s2.ComputeHash(data);
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

                    }
                    Console.WriteLine("{0}mb in {1} on {2}, {3}mb/sec", data.Length / (1024 * 1024), time.TotalSeconds, IntPtr.Size == 4 ? "x86" : "amd64", (data.Length / (1024 * 1024)) / time.TotalSeconds);
                }
            }
        }
    }
}
