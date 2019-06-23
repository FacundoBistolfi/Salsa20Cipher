using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Salsa20Prueba
{
    static class Salsa20cipher
    {

        public static UInt32[] getExpansionBlock(String key, String nonce, ulong blockNumber)
        {
            int longitud = key.Length;
            if ((longitud != 32) && (longitud != 16) && (longitud != 10))
                throw new Exception("Wrong key size");
            if (nonce.Length != 8)
                throw new Exception("Wrong nonce size");

            bool is32bytes = (longitud == 32);
            //Esto no es del todo correcto, se debe rellenar con ceros
            if (longitud == 10)
                key += "      ";

            UInt32[] keyBlock = stringToUint32Array(key);
            UInt32[] nonceBlock = stringToUint32Array(nonce);
            UInt32[] numberBlock = uInt64ToUint32Array(blockNumber);
            UInt32[] constBlock = getExpansionConstant(longitud);
            UInt32[] expansionBlock = new UInt32[16];

            //Armo el bloque de expansion
            //Armo la diagonal con el bloque de constantes
            for (int i = 0; i < 4; i++)
                expansionBlock[i*5] = constBlock[i];
            //Asigno las primeras 4 words de la key
            for (int i = 0; i < 4; i++)
                expansionBlock[i + 1] = keyBlock[i];
            //Asigno las words del nonce
            for (int i = 0; i < 2; i++)
                expansionBlock[i + 6] = nonceBlock[i];
            //Asigno las words del block number
            for (int i = 0; i < 2; i++)
                expansionBlock[i + 8] = numberBlock[i];
            //Asigno las 4 words de la key que faltan, en caso de no ser una key de 32 bytes se repiten las primeras
            for (int i = 0; i < 4; i++)
                expansionBlock[i + 11] = keyBlock[i + (is32bytes?4:0)];
            return expansionBlock;
        }


        public static void doubleRound(ref UInt32[] b)
        {
          columnRound(ref b);
          rowRound(ref b);
        }

        public static void rowRound(ref UInt32[] b)
        {
            quarterRoundS20(ref b[0], ref b[1], ref b[2], ref b[3]);
            quarterRoundS20(ref b[5], ref b[6], ref b[7], ref b[4]);
            quarterRoundS20(ref b[10], ref b[11], ref b[8], ref b[9]);
            quarterRoundS20(ref b[15], ref b[12], ref b[13], ref b[14]);
        }

        public static void columnRound(ref UInt32[] b)
        {
            quarterRoundS20(ref b[0], ref b[4], ref b[8], ref b[12]);
            quarterRoundS20(ref b[5], ref b[9], ref b[13], ref b[1]);
            quarterRoundS20(ref b[10], ref b[14], ref b[2], ref b[6]);
            quarterRoundS20(ref b[15], ref b[3], ref b[7], ref b[11]);
        }

        public static void quarterRoundS20(ref UInt32 a, ref UInt32 b, ref UInt32 c, ref UInt32 d)
        {
            b = b ^ rotl(a + d, 7);
            c = c ^ rotl(b + a, 9);
            d = d ^ rotl(c + b, 13);
            a = a ^ rotl(d + c, 18);
        }


        private static UInt32 rotl(UInt32 value, int shift)
        {
            return (value << shift) | (value >> (32 - shift));
        }


        public static UInt32[] getExpansionConstant(int length)
        {
            UInt32[] c = new UInt32[4];
            String s = "";

            if (length == 32)
                s = "expand 32-byte k";
            else if (length == 16)
                s = "expand 16-byte k";
            else if (length == 10)
                s = "expand 10-byte k";

            return stringToUint32Array(s);
        }


        //Conversiones entre arrays de words de 4 bytes (UInt32) y Strings
        public static UInt32[] stringToUint32Array(String s)
        {
            //Si faltan caracteres para tener grupos de 4 bytes relleno con espacios
            String add = "";
            if (s.Length % 4 != 0)
                for (int i = 0; i < (4 - s.Length % 4); i++)
                    add += " ";
            s += add;
                
            int cant = ((s.Length/4));
            UInt32[] c = new UInt32[cant];
            Byte[] b = Encoding.ASCII.GetBytes(s);
            for (int i = 0; i < c.Length; i++)
                c[i] = BitConverter.ToUInt32(b, i * 4);
            return c;
        }

        public static UInt32[] uInt64ToUint32Array(UInt64 l)
        {
            UInt32[] c = new UInt32[2];
            Byte[] b = BitConverter.GetBytes(l);
            for (int i = 0; i < c.Length; i++)
                c[i] = BitConverter.ToUInt32(b, i * 4);
            return c;
        }

        public static String uint32arrayToString(UInt32[] array)
        {
            String decoded = "";
            for (int i = 0; i < array.Length; i++)
            {
                decoded += Encoding.ASCII.GetString(BitConverter.GetBytes(array[i]));
            }
            return decoded;
        }

        public static UInt64 uint32arrayToUInt64(UInt32[] array)
        {
            if (array.Length != 2)
                throw new Exception("incorrect size");
            Byte[] bytes = new Byte[8];
            BitConverter.GetBytes(array[0]).CopyTo(bytes,0);
            BitConverter.GetBytes(array[1]).CopyTo(bytes,4);
            return BitConverter.ToUInt64(bytes,0);
            
        }

    }
}
