using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Salsa20Prueba
{
    class Program
    {
        static void Main(string[] args)
        {
            
            String key = "1234567890123456abcdefghABCDEFGH";
            String nonce = "ABCDabcd";
            ulong number = 1;
            var watch = System.Diagnostics.Stopwatch.StartNew();
            UInt32[] expansionBlock = Salsa20cipher.getExpansionBlock(key, nonce, number);
            watch.Stop();
            var elapsedMs = watch.ElapsedMilliseconds;
            
            UInt32 v1 = 10;
            UInt32 v2 = 1000;
            UInt32 v3 = v1 ^ v2;
            Console.WriteLine("asd: " + v3);


            Console.ReadKey();
            
        }

        
    }
}
