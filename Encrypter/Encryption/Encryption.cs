using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace NetProtectEncrypter.Encrypter.Encryption
{
    class Encryption
    {
        public static byte[] EncryptAES(byte[] input, string Pass)
        {
            RijndaelManaged AES = new RijndaelManaged();
            byte[] hash = new byte[32];
            byte[] temp = new MD5CryptoServiceProvider().ComputeHash(Encoding.ASCII.GetBytes(Pass));
            Array.Copy(temp, 0, hash, 0, 16);
            Array.Copy(temp, 0, hash, 15, 16);
            AES.Key = hash;
            AES.Mode = CipherMode.ECB;
            ICryptoTransform DESEncrypter = AES.CreateEncryptor();
            return DESEncrypter.TransformFinalBlock(input, 0, input.Length);
        }
        public static byte[] EncryptXOR(byte[] input, byte xor_key)
        {
            for (int i = 0; i < input.Length; i++)
            {
                input[i] ^= xor_key;
            }
            return input;
        }

        public static byte[] EncryptRSA(byte[] input, byte[] key)
        {
            return new byte[0];
        }
    }
}
