using System;
using System.Text;
using DZen.Security.Cryptography;

namespace DZen.Security.Cryptography.SpeedTest
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
                foreach (SHA3 sha3 in new object[] { SHA3.Create("sha3-256") })
                {
                    sha3.ComputeHash(UTF8Encoding.UTF8.GetBytes("Hello"));
                    rand.NextBytes(data);
                    
                    DateTime begin = DateTime.UtcNow;
                    sha3.ComputeHash(data);
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
