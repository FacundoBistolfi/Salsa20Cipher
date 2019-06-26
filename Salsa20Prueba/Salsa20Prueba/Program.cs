using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;


namespace Salsa20Prueba
{
    class Program
    {
        static void Main(string[] args)
        {
            /*
            //String key = "1234567890123456abcdefghABCDEFGH";
            //String key = "1234567890123456";
            String key = "1234567890123456";
            String nonce = "ABCDabcd";
            ulong number = 1;


            var watch = System.Diagnostics.Stopwatch.StartNew();
            UInt32[] hash = Salsa20cipher.hashSalsa20(Encoding.ASCII.GetBytes(key), Encoding.ASCII.GetBytes(nonce), number);
            watch.Stop();
            var elapsedMs = watch.ElapsedMilliseconds;

            Console.WriteLine("HASH VALUES: ");
            Console.WriteLine("Key: " + key);
            Console.WriteLine("Nonce: " + nonce);
            Console.WriteLine("Block number: " + number);
            Console.WriteLine("Hash time: " + elapsedMs + " ms");
            Console.WriteLine("HASH: ");
            mostrarBloque(hash);

            */
            String[] tamaños = { "1kb", "100kb", "500kb", "1mb", "10mb", "100mb", "250mb", "500mb", "1gb" };
            byte[] key = Encoding.ASCII.GetBytes("1234567890123456");
            byte[] nonce = Encoding.ASCII.GetBytes("ABCDabcd");

            string salida = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), "salida ");

            for (int j = 0; j < 3; j++)
            {


                for (int i = 0; i < tamaños.Length; i++)
                {

                    Console.WriteLine("Tamaño: " + tamaños[i]);
                    string inPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), tamaños[i]);

                    long t = encriptarArchivo(key, nonce, inPath, salida + tamaños[i]);

                    Console.WriteLine("Tardó " + t);
                }

            }

            Console.ReadKey();
            
        }

       

        public static long encriptarArchivo(byte[] key, byte[] nonce, String inPath, String outPath)
        {
            var watch = System.Diagnostics.Stopwatch.StartNew();
            FileStream inFs = new FileStream(inPath, FileMode.Open, FileAccess.Read);
            FileStream outFs = new FileStream(outPath, FileMode.Create);
            byte[] bufferIn = new byte[64];
            int fileOffset = 0;
            ulong i = 0;

            while (fileOffset < inFs.Length)
            {
                inFs.Seek(fileOffset, SeekOrigin.Begin);
                bufferIn = new byte[64];
                int bytesRead = inFs.Read(bufferIn, 0, 64);
                outFs.Write(Salsa20cipher.cryptBlock(key, nonce, i, bufferIn), 0, 64);
                fileOffset += 64;
                i++;
            }
            inFs.Close();
            outFs.Close(); watch.Stop();
            return watch.ElapsedMilliseconds;

        }


    }
    
    

}
