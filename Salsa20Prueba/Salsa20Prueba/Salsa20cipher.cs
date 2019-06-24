using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Salsa20Prueba
{
    static class Salsa20cipher
    {

        //**********************
        // FUNCIONES DE ENCRIPTAR MENSAJE
        //**********************


        //Funcion que encripta un array de bytes
        public static byte[] crypt(String key, String nonce, int keyLength, byte[] message)
        {
            //Creo el espacio para el mensaje encriptado
            int cant = (message.Length % 64 == 0) ? message.Length : message.Length + (64 - message.Length%64);
            byte[] encriptado = new byte[cant];

            int i = 0;
            while(i < message.Length/64){



                i++;
            }

            return encriptado;
        }

        //Funcion que encripta un array de bytes sin keyLength
        public static byte[] crypt(String key, String nonce, byte[] message)
        {
            return crypt(key, nonce, 0, message);
        }

        //**********************
        // FUNCIONES DE ENCRIPTAR BLOQUE
        //**********************

        //Funcion que encripta un bloque de 64 bytes en byte[]
        public static byte[] cryptBlock(String key, String nonce, ulong blockNumber, int keyLength, byte[] block)
        {
            if (block.Length != 64)
                throw new Exception("Wrong block length");

            //Paso el array de byte a un array de UInt32
            UInt32[] blockint32 = new UInt32[16];
            for (int i = 0; i < 64; i++)
                blockint32[i] = BitConverter.ToUInt32(block, i * 4);
            
            //Encripto el bloque
            blockint32 = cryptBlock(key, nonce, blockNumber, keyLength, blockint32);

            //Paso el array de Uint32 a byte
            for (int i = 0; i < 16; i++)
            {
                byte[] bytes = BitConverter.GetBytes(blockint32[i]);
                for (int j = 0; j < 4; j++)
                    block[i * 4 + j] = bytes[j];
            }

            return block;
        }
        //Sobrecarga de la funcion sin keyLength
        public static byte[] cryptBlock(String key, String nonce, ulong blockNumber, byte[] block)
        {
            return cryptBlock(key,nonce,blockNumber,0,block);
        }

        //Funcion que encripta un bloque de 64 bytes dado en UInt32[]
        public static UInt32[] cryptBlock(String key, String nonce, ulong blockNumber, int keyLength, UInt32[] block)
        {
            if (block.Length != 16)
                throw new Exception("Wrong block length");

            UInt32[] hash = hashSalsa20(key,nonce,blockNumber,keyLength);
            for(int i=0;i<16;i++)
                block[i] = block[i]^hash[i];

            return block;
        }

        //Sobrecarga de la funcion sin keyLength
        public static UInt32[] cryptBlock(String key, String nonce, ulong blockNumber, UInt32[] block)
        {
            return cryptBlock(key, nonce, blockNumber, 0, block);
        }


        //**********************
        // FUNCIONES DE HASH
        //**********************

        //Sobrecarga de la funcion de hash sin keyLength
        public static UInt32[] hashSalsa20(String key, String nonce, ulong blockNumber)
        {
            return hashSalsa20(key, nonce, blockNumber, 0);
        }

        //Funcion que retorna el hash del bloque a cifrar
        public static UInt32[] hashSalsa20(String key, String nonce, ulong blockNumber, int keyLength)
        {
            //Obtengo el bloque con la funcion de expansion, guardo una copia del mismo para el final del hash
            UInt32[] block = getExpansionBlock(key, nonce, blockNumber, keyLength);
            UInt32[] block2 = new UInt32[16];
            block.CopyTo(block2, 0);

            //Hago las 10 doble vueltas
            for (int i = 0; i < 10; i++)
            {
                doubleRound(ref block);
            }

            //Sumo el bloque "mixeado" al bloque original, asi se evita que se pueda recuperar la clave y otros datos
            //de este bloque
            for (int i = 0; i < 16; i++)
            {
                block[i] = block[i] + block2[i];
            }

            return block;
        }

        //*************************
        // FUNCIONES DE EXPANSION
        //*************************

        //Funcion que crea el bloque de expansion a partir de la key, el nonce, el numero de bloque y el tamaño de key indicado
        public static UInt32[] getExpansionBlock(UInt32[] key, UInt32[] nonce, UInt32[] blockNumber, int keyLength)
        {
            //Se verifican las longitudes de los arrays
            if ((keyLength == 32) && (key.Length != 8))
                throw new Exception("Wrong keyLength given");
            if ((keyLength == 16) && (key.Length != 4))
                throw new Exception("Wrong keyLength given");
            if ((keyLength == 10) && (key.Length != 4))
                throw new Exception("Wrong keyLength given");

            //Se obtiene la constante de expansion que depende de la longitud de la key
            UInt32[] constBlock = getExpansionConstant(keyLength);
            UInt32[] expansionBlock = new UInt32[16];

            //Armo el bloque de expansion
            //Armo la diagonal con el bloque de constantes
            for (int i = 0; i < 4; i++)
                expansionBlock[i * 5] = constBlock[i];
            //Asigno las primeras 4 words de la key
            for (int i = 0; i < 4; i++)
                expansionBlock[i + 1] = key[i];
            //Asigno las words del nonce
            for (int i = 0; i < 2; i++)
                expansionBlock[i + 6] = nonce[i];
            //Asigno las words del block number
            for (int i = 0; i < 2; i++)
                expansionBlock[i + 8] = blockNumber[i];
            //Asigno las 4 words de la key que faltan, en caso de no ser una key de 32 bytes se repiten las primeras
            for (int i = 0; i < 4; i++)
                expansionBlock[i + 11] = key[i + ((keyLength == 32) ? 4 : 0)];
            return expansionBlock;
        }

        //Sobrecarga de la funcion para admitir como entradas Strings
        public static UInt32[] getExpansionBlock(String key, String nonce, ulong blockNumber)
        {
            return getExpansionBlock(key, nonce, blockNumber, 0);
        }

        //Sobrecarga de la funcion para admitir como entradas Strings y tamaño de key
        public static UInt32[] getExpansionBlock(String key, String nonce, ulong blockNumber, int keyLength)
        {
            //Se verifica que la cantidad de caracteres en la key y en el nonce sean los adecuados,
            //y en caso de que se haya indicando un tamaño de key, este sea 10, 16 o 32
            if (key.Length > 32)
                throw new Exception("Wrong key size");
            if (nonce.Length > 8)
                throw new Exception("Wrong nonce size");
            if (keyLength != 0)
                if ((keyLength != 10) && (keyLength != 16) && (keyLength != 32))
                    throw new Exception("Wrong key size given");


            //Si no se indica la longitud de la key, esta se asigna a la longitud mas cercana 
            // - si tiene mas de 16 bytes, será una key de 32 bytes
            // - si tiene entre 16 y 11 bytes, será de 16
            // - si tiene 10 o menos bytes, será de 10;

            int longitud = 0;
            if (keyLength == 0)
                longitud = (key.Length > 16) ? 32 : (key.Length > 10) ? 16 : 10;
            else
                longitud = keyLength;

            //Se pasan los strings a arrays de words, indicando el tamaño minimo que debe tener el de la key
            //Esto se hace para que con tamaños menores la función de conversion rellene con ceros al final
            UInt32[] keyBlock = stringToUint32Array(key, (longitud == 32) ? 32 : 16);
            UInt32[] nonceBlock = stringToUint32Array(nonce, 8);
            UInt32[] numberBlock = uInt64ToUint32Array(blockNumber);


            return getExpansionBlock(keyBlock, nonceBlock, numberBlock, longitud);
        }

        //Funcion que retorna la constante de expansion utilizada en la funcion de expansion.
        //Esta constante (array) depende de la longitud de la clave (10, 16 o 32 bytes)
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

        //**********************
        // FUNCIONES DE RONDA
        //**********************

        //Funcion que ejecuta una vuelta para cada columna y otra para cada vuelta
        public static void doubleRound(ref UInt32[] b)
        {
          columnRound(ref b);
          rowRound(ref b);
        }

        //Funcion que realiza un cuarto de vuelta para cada fila
        public static void rowRound(ref UInt32[] b)
        {
            quarterRoundS20(ref b[0], ref b[1], ref b[2], ref b[3]);
            quarterRoundS20(ref b[5], ref b[6], ref b[7], ref b[4]);
            quarterRoundS20(ref b[10], ref b[11], ref b[8], ref b[9]);
            quarterRoundS20(ref b[15], ref b[12], ref b[13], ref b[14]);
        }

        //Funcion que realiza un cuarto de vuelta para cada columna
        public static void columnRound(ref UInt32[] b)
        {
            quarterRoundS20(ref b[0], ref b[4], ref b[8], ref b[12]);
            quarterRoundS20(ref b[5], ref b[9], ref b[13], ref b[1]);
            quarterRoundS20(ref b[10], ref b[14], ref b[2], ref b[6]);
            quarterRoundS20(ref b[15], ref b[3], ref b[7], ref b[11]);
        }

        //Funcion de "cuarto de vuelta" que es el corazón del hash de Salsa20, basicamente una funcion del tipo add-rotate-xor
        //que toma de a 4 words del bloque
        public static void quarterRoundS20(ref UInt32 a, ref UInt32 b, ref UInt32 c, ref UInt32 d)
        {
            b = b ^ rotl(a + d, 7);
            c = c ^ rotl(b + a, 9);
            d = d ^ rotl(c + b, 13);
            a = a ^ rotl(d + c, 18);
        }

        //Funcion que simula la rotación de bits (por defecto en bloques de 32 bytes)

        private static UInt32 rotl(UInt32 value, int shift)
        {
            return rotl(value,shift,32);
        }


        private static UInt32 rotl(UInt32 value, int shift, int mode)
        {
            return (value << shift) | (value >> (32 - shift));
        }

        //**********************
        // FUNCIONES DE CONVERSION
        //**********************

        //Conversiones entre arrays de words de 4 bytes (UInt32), Strings y longs (UInt64)

        //Funcion que convierte un string a un array de UInt32 , se puede seleccionar tambien una cantidad minima de bytes
        //(si sobran se rellenan con ceros)
        public static UInt32[] stringToUint32Array(String s)
        {
            return stringToUint32Array(s, 0);
        }
        public static UInt32[] stringToUint32Array(String s, int minBytes)
        {
            //Paso la cadena a un array de bytes, luego este array de bytes lo paso a otro que tenga grupos de 4 bytes formados   
            Byte[] bytes = Encoding.ASCII.GetBytes(s);
            int cant = (bytes.Length % 4 == 0) ? bytes.Length : bytes.Length + (4 - bytes.Length%4);
            if (cant < minBytes) cant = minBytes;
            Byte[] b = new Byte[cant];
            bytes.CopyTo(b,0);

            //Creo el array de words (4 bytes)
            UInt32[] c = new UInt32[b.Length/4];

            //Hago el pasaje de bytes a words
            for (int i = 0; i < c.Length; i++)
                c[i] = BitConverter.ToUInt32(b, i * 4);

            return c;
        }

        //Funcion que convierte un unsigned int de 64 bytes en un array de UInt32
        public static UInt32[] uInt64ToUint32Array(UInt64 l)
        {
            UInt32[] c = new UInt32[2];
            Byte[] b = BitConverter.GetBytes(l);
            for (int i = 0; i < c.Length; i++)
                c[i] = BitConverter.ToUInt32(b, i * 4);
            return c;
        }

        //Funcion que convierte un array de UInt32 a un string (En ASCII)
        public static String uint32arrayToString(UInt32[] array)
        {
            String decoded = "";
            for (int i = 0; i < array.Length; i++)
            {
                decoded += Encoding.ASCII.GetString(BitConverter.GetBytes(array[i]));
            }
            return decoded;
        }

        //Funcion que convierte un array de dos UInt32 a un UInt64 
        public static UInt64 uint32arrayToUInt64(UInt32[] array)
        {
            if (array.Length != 2)
                throw new Exception("incorrect size");
            Byte[] bytes = new Byte[8];
            BitConverter.GetBytes(array[0]).CopyTo(bytes,0);
            BitConverter.GetBytes(array[1]).CopyTo(bytes,4);
            return BitConverter.ToUInt64(bytes,0);
            
        }

        public static void mostrarBloque(UInt32[] b)
        {
            for (int i = 0; i < b.Length; i++)
            {
                Console.WriteLine(" - " + b[i] + "\t" + b[i].ToString("X8"));
            }
        }

    }
}
