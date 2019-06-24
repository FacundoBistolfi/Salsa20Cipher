using System;
using System.Text;

namespace Salsa20Cipher
{
    static class Salsa20cipher
    {
        //**********************
        // CONSTANTES
        //**********************

        public static int KEY_32BYTE = 32;
        public static int KEY_16BYTE = 16;
        public static int KEY_10BYTE = 10;
        private static String CONST_32BYTE = "expand 32-byte k";
        private static String CONST_16BYTE = "expand 16-byte k";
        private static String CONST_10BYTE = "expand 10-byte k";


        //**********************
        // FUNCIONES DE ENCRIPTAR MENSAJE
        //**********************


        //Funcion que encripta un array de bytes
        public static byte[] crypt(byte[] key, byte[] nonce, int keyLength, byte[] message)
        {
            //Creo el espacio para el mensaje encriptado
            int cant = (message.Length % 64 == 0) ? message.Length : message.Length + (64 - message.Length % 64);
            byte[] encriptado = new byte[cant];
            byte[] bloque = new byte[64];

            //Recorro todos los bloques y los encripto
            int j, i = 0;
            while (i < message.Length / 64)
            {
                for (j = 0; j < 64; j++)
                    bloque[j] = message[i * 64 + j];
                bloque = cryptBlock(key, nonce, (ulong)i, bloque);
                for (j = 0; j < 64; j++)
                    encriptado[i * 64 + j] = bloque[j];
                i++;

            }
            //Si me faltó parte del mensaje
            if (cant > message.Length)
            {
                int cantFalta = (message.Length - (i * 64));
                bloque = new byte[64];
                for (j = 0; j < cantFalta; j++)
                    bloque[j] = message[i * 64 + j];
                bloque = cryptBlock(key, nonce, (ulong)i, bloque);
                for (j = 0; j < 64; j++)
                    encriptado[i * 64 + j] = bloque[j];
            }

            return encriptado;
        }

        //Funcion que encripta un array de bytes sin keyLength
        public static byte[] crypt(byte[] key, byte[] nonce, byte[] message)
        {
            return crypt(key, nonce, 0, message);
        }

        //**********************
        // FUNCIONES DE ENCRIPTAR BLOQUE
        //**********************

        //Funcion que encripta un bloque de 64 bytes en byte[]
        private static byte[] cryptBlock(byte[] key, byte[] nonce, ulong blockNumber, int keyLength, byte[] block)
        {
            if (block.Length != 64) throw new ArgumentOutOfRangeException(nameof(block), block.Length, "Wrong block length");

            //Paso el array de byte a un array de UInt32
            UInt32[] blockint32 = new UInt32[16];

            for (int i = 0; i < 16; i++)
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
        private static byte[] cryptBlock(byte[] key, byte[] nonce, ulong blockNumber, byte[] block)
        {
            return cryptBlock(key, nonce, blockNumber, 0, block);
        }

        //Funcion que encripta un bloque de 64 bytes dado en UInt32[]
        private static UInt32[] cryptBlock(byte[] key, byte[] nonce, ulong blockNumber, int keyLength, UInt32[] block)
        {
            if (block.Length != 16) throw new ArgumentOutOfRangeException(nameof(block), block.Length, "Wrong block length");

            UInt32[] hash = hashSalsa20(key, nonce, blockNumber, keyLength);

            for (int i = 0; i < 16; i++) block[i] = block[i] ^ hash[i];

            return block;
        }

        //Sobrecarga de la funcion sin keyLength
        private static UInt32[] cryptBlock(byte[] key, byte[] nonce, ulong blockNumber, UInt32[] block)
        {
            return cryptBlock(key, nonce, blockNumber, 0, block);
        }

        //**********************
        // FUNCIONES DE HASH
        //**********************

        //Sobrecarga de la funcion de hash sin keyLength
        private static UInt32[] hashSalsa20(byte[] key, byte[] nonce, ulong blockNumber)
        {
            return hashSalsa20(key, nonce, blockNumber, 0);
        }

        //Funcion que retorna el hash del bloque a cifrar
        private static UInt32[] hashSalsa20(byte[] key, byte[] nonce, ulong blockNumber, int keyLength)
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
        private static UInt32[] getExpansionBlock(UInt32[] key, UInt32[] nonce, UInt32[] blockNumber, int keyLength)
        {
            //Se verifican las longitudes de los arrays
            if ((keyLength == KEY_32BYTE) && (key.Length != 8)) throw new ArgumentOutOfRangeException(nameof(keyLength), keyLength, "Wrong keyLength given");
            if ((keyLength == KEY_16BYTE) && (key.Length != 4)) throw new ArgumentOutOfRangeException(nameof(keyLength), keyLength, "Wrong keyLength given");
            if ((keyLength == KEY_10BYTE) && (key.Length != 4)) throw new ArgumentOutOfRangeException(nameof(keyLength), keyLength, "Wrong keyLength given");

            //Se obtiene la constante de expansion que depende de la longitud de la key
            UInt32[] constBlock = getExpansionConstant(keyLength);
            UInt32[] expansionBlock = new UInt32[16];

            int repite = (keyLength == KEY_32BYTE) ? 4 : 0;

            //Armo el bloque de expansion
            //Armo la diagonal con el bloque de constantes
            for (int i = 0; i < 4; i++)
            {
                expansionBlock[i * 5] = constBlock[i];
                //Asigno las primeras 4 words de la key
                expansionBlock[i + 1] = key[i];
                //Asigno las 4 words de la key que faltan, en caso de no ser una key de 32 bytes se repiten las primeras
                expansionBlock[i + 11] = key[i + repite];
            }

            for (int i = 0; i < 2; i++)
            {
                //Asigno las words del nonce
                expansionBlock[i + 6] = nonce[i];
                //Asigno las words del block number            
                expansionBlock[i + 8] = blockNumber[i];
            }

            return expansionBlock;
        }

        //Sobrecarga de la funcion para admitir como entradas Strings
        private static UInt32[] getExpansionBlock(byte[] key, byte[] nonce, ulong blockNumber)
        {
            return getExpansionBlock(key, nonce, blockNumber, 0);
        }

        //Sobrecarga de la funcion para admitir como entradas Strings y tamaño de key
        private static UInt32[] getExpansionBlock(byte[] key, byte[] nonce, ulong blockNumber, int keyLength)
        {
            //Se verifica que la cantidad de caracteres en la key y en el nonce sean los adecuados,
            //y en caso de que se haya indicando un tamaño de key, este sea 10, 16 o 32
            if (key.Length > 32) throw new ArgumentOutOfRangeException(nameof(key), key.Length, "Wrong key size");
            if (nonce.Length > 8) throw new ArgumentOutOfRangeException(nameof(nonce), nonce.Length, "Wrong nonce size");
            if (keyLength != 0 && (keyLength != 10) && (keyLength != 16) && (keyLength != 32)) throw new ArgumentOutOfRangeException(nameof(keyLength), keyLength, "Wrong key size given");

            //Si no se indica la longitud de la key, esta se asigna a la longitud mas cercana 
            // - si tiene mas de 16 bytes, será una key de 32 bytes
            // - si tiene entre 16 y 11 bytes, será de 16
            // - si tiene 10 o menos bytes, será de 10;

            int longitud = 0;
            if (keyLength == 0)
                longitud = (key.Length > KEY_16BYTE) ? KEY_32BYTE : (key.Length > KEY_10BYTE) ? KEY_16BYTE : KEY_10BYTE;
            else
                longitud = keyLength;

            //Se pasan los strings a arrays de words, indicando el tamaño minimo que debe tener el de la key
            //Esto se hace para que con tamaños menores la función de conversion rellene con ceros al final
            UInt32[] keyBlock = byteToWord(key, (longitud == KEY_32BYTE) ? KEY_32BYTE : KEY_16BYTE);
            UInt32[] nonceBlock = byteToWord(nonce, 8);
            UInt32[] numberBlock = longToWord(blockNumber);

            return getExpansionBlock(keyBlock, nonceBlock, numberBlock, longitud);
        }

        //Funcion que retorna la constante de expansion utilizada en la funcion de expansion.
        //Esta constante (array) depende de la longitud de la clave (10, 16 o 32 bytes)
        private static UInt32[] getExpansionConstant(int length)
        {
            UInt32[] c = new UInt32[4];
            String s = "";

            if (length == KEY_32BYTE)
                s = CONST_32BYTE;
            else if (length == KEY_16BYTE)
                s = CONST_16BYTE;
            else if (length == KEY_10BYTE)
                s = CONST_10BYTE;

            return stringToWord(s);
        }

        //**********************
        // FUNCIONES DE RONDA
        //**********************

        //Funcion que ejecuta una vuelta para cada columna y otra para cada vuelta
        private static void doubleRound(ref UInt32[] b)
        {
            columnRound(ref b);
            rowRound(ref b);
        }

        //Funcion que realiza un cuarto de vuelta para cada fila
        private static void rowRound(ref UInt32[] b)
        {
            quarterRoundS20(ref b[0], ref b[1], ref b[2], ref b[3]);
            quarterRoundS20(ref b[5], ref b[6], ref b[7], ref b[4]);
            quarterRoundS20(ref b[10], ref b[11], ref b[8], ref b[9]);
            quarterRoundS20(ref b[15], ref b[12], ref b[13], ref b[14]);
        }

        //Funcion que realiza un cuarto de vuelta para cada columna
        private static void columnRound(ref UInt32[] b)
        {
            quarterRoundS20(ref b[0], ref b[4], ref b[8], ref b[12]);
            quarterRoundS20(ref b[5], ref b[9], ref b[13], ref b[1]);
            quarterRoundS20(ref b[10], ref b[14], ref b[2], ref b[6]);
            quarterRoundS20(ref b[15], ref b[3], ref b[7], ref b[11]);
        }

        //Funcion de "cuarto de vuelta" que es el corazón del hash de Salsa20, basicamente una funcion del tipo add-rotate-xor
        //que toma de a 4 words del bloque
        private static void quarterRoundS20(ref UInt32 a, ref UInt32 b, ref UInt32 c, ref UInt32 d)
        {
            b = b ^ rotl(a + d, 7);
            c = c ^ rotl(b + a, 9);
            d = d ^ rotl(c + b, 13);
            a = a ^ rotl(d + c, 18);
        }

        //Funcion que simula la rotación de bits (por defecto en bloques de 32 bytes)

        private static UInt32 rotl(UInt32 value, int shift)
        {
            return rotl(value, shift, 32);
        }


        private static UInt32 rotl(UInt32 value, int shift, int mode)
        {
            return (value << shift) | (value >> (32 - shift));
        }

        //**********************
        // FUNCIONES DE CONVERSION
        //**********************

        //Conversiones entre arrays de words de 4 bytes (UInt32), Strings, longs (UInt64) y arrays de bytes

        //Funcion que convierte un string a un array de UInt32 , se puede seleccionar tambien una cantidad minima de bytes
        //(si sobran se rellenan con ceros)
        private static UInt32[] stringToWord(String s)
        {
            return stringToWord(s, 0);
        }
        private static UInt32[] stringToWord(String s, int minBytes)
        {
            //Paso la cadena a un array de bytes
            return byteToWord(Encoding.ASCII.GetBytes(s), minBytes);
        }


        //Funcion que convierte un array de bytes en un array de UInt32
        private static UInt32[] byteToWord(byte[] bytes, int minBytes)
        {
            //Paso el array a otro que tenga grupos de 4 bytes formados   
            int cant = (bytes.Length % 4 == 0) ? bytes.Length : bytes.Length + (4 - bytes.Length % 4);
            if (cant < minBytes) cant = minBytes;
            byte[] b = new byte[cant];
            bytes.CopyTo(b, 0);

            //Creo el array de words (4 bytes)
            UInt32[] c = new UInt32[b.Length / 4];

            //Hago el pasaje de bytes a words
            for (int i = 0; i < c.Length; i++)
                c[i] = BitConverter.ToUInt32(b, i * 4);

            return c;
        }

        //Sobrecarga de la funcion
        private static UInt32[] byteToWord(byte[] bytes)
        {
            return byteToWord(bytes, 0);
        }

        //Funcion que convierte un unsigned int de 64 bytes en un array de UInt32
        private static UInt32[] longToWord(UInt64 l)
        {
            UInt32[] c = new UInt32[2];
            byte[] b = BitConverter.GetBytes(l);
            for (int i = 0; i < c.Length; i++)
                c[i] = BitConverter.ToUInt32(b, i * 4);
            return c;
        }

        //Funcion que convierte un array de UInt32 a un string (En ASCII)
        private static String wordToString(UInt32[] array)
        {
            String decoded = "";
            for (int i = 0; i < array.Length; i++)
            {
                decoded += Encoding.ASCII.GetString(BitConverter.GetBytes(array[i]));
            }
            return decoded;
        }

        //Funcion que convierte un array de dos UInt32 a un UInt64 
        private static UInt64 wordToLong(UInt32[] array)
        {
            if (array.Length != 2) throw new ArgumentOutOfRangeException(nameof(array), array.Length, "incorrect size");
            byte[] bytes = new byte[8];
            BitConverter.GetBytes(array[0]).CopyTo(bytes, 0);
            BitConverter.GetBytes(array[1]).CopyTo(bytes, 4);
            return BitConverter.ToUInt64(bytes, 0);
        }
    }
}
