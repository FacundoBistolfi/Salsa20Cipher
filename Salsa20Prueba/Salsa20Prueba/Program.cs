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

            byte[] key = Encoding.ASCII.GetBytes("1234567890123456");
            byte[] nonce = Encoding.ASCII.GetBytes("ABCDabcd");
            //StreamReader inFile = new StreamReader();
            //byte[] message = Encoding.UTF8.GetBytes(inFile.ReadToEnd());
            byte[] message = File.ReadAllBytes(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), "in.txt"));
            
            var watch = System.Diagnostics.Stopwatch.StartNew();
            byte[] crypt = Salsa20cipher.crypt(key, nonce, message);
            watch.Stop();
            Console.WriteLine("Primera encriptación duró " + watch.ElapsedMilliseconds + " ms");
            escribirArchivo("primero.txt", crypt);
                

            var watch2 = System.Diagnostics.Stopwatch.StartNew();
            byte[] crypt2 = Salsa20cipher.crypt(key, nonce, crypt);
            watch2.Stop();
            Console.WriteLine("Segunda encriptación duró " + watch2.ElapsedMilliseconds + " ms");
            escribirArchivo("segundo.txt", crypt2);
            escribirArchivo("textoplano.txt", message);


            

            Console.ReadKey();
            
        }

        private void mostrarBloque(UInt32[] b)
        {
            for (int i = 0; i < b.Length; i++)
            {
                Console.WriteLine(" - " + b[i] + "\t" + b[i].ToString("X8"));
            }
        }

        private static void escribirArchivo(String nombre, byte[] bytes){
            string docPath = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
            //StreamWriter outputFile = new StreamWriter(Path.Combine(docPath, nombre));
            //outputFile.WriteLine(Encoding.UTF8.GetString(texto));
            //outputFile.Close();
            File.WriteAllBytes(Path.Combine(docPath, nombre), bytes);

        }
    }
    
    

}
