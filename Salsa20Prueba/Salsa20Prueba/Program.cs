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
            
            //String key = "1234567890123456abcdefghABCDEFGH";
            //String key = "1234567890123456";
            String key = "1234567890123456";

            String nonce = "ABCDabcd";
            ulong number = 1;

            var watch = System.Diagnostics.Stopwatch.StartNew();
            UInt32[] hash = Salsa20cipher.hashSalsa20(key, nonce, number);
            watch.Stop();
            var elapsedMs = watch.ElapsedMilliseconds;

            Console.WriteLine("HASH VALUES: ");
            Console.WriteLine("Key: " + key);
            Console.WriteLine("Nonce: " + nonce);
            Console.WriteLine("Block number: " + number);
            Console.WriteLine("Hash time: " + elapsedMs + " ms");
            Console.WriteLine("HASH: ");
            Salsa20cipher.mostrarBloque(hash);

            

            Console.ReadKey();
            
        }

        
    }
}
