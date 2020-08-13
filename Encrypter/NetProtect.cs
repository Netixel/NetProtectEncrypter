using Mono.Cecil;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using PeNet;
using NetProtectEncrypter.Encrypter.Wrappers;
using System.Security.Cryptography;
using System.Net;

namespace NetProtectEncrypter.Encrypter
{
    class NetProtect
    {
        private readonly byte XOR_BYTE = 0x16;
        private readonly string WorkDirectory;

        private ProtectableAssembly Assembly;

        private string output_file;
        private string aes_key;
        private string UPLOAD_URL;

        public NetProtect(string input_file, string output_file, string aes_key, string upload_url = "")
        {
            this.UPLOAD_URL = upload_url;
            WorkDirectory = $"{Path.GetTempPath()}\\NetProtect";
            Directory.CreateDirectory(WorkDirectory);

            this.output_file = output_file;
            this.aes_key = aes_key;
            Assembly = new ProtectableAssembly(input_file);
        }

        public int ProtectAssembly() //each protection should be its own "step" that kinda acts like a module (this means we *could* make this modular)
        {
            //TODO: obfuscate strings
            
            //TODO: obfuscate numbers

            //TODO: obfuscate calls

            //TODO: obfuscate flow

            Program.PrintV("=== Calculating Hashes ===");
            HandleHashes();
            WriteToDisk(true,"temp_1.exe");

            Program.PrintV("=== Calculating Hashes 2x ===");
            HandleHashes();
            WriteToDisk(true,"temp_2.exe");

            Program.PrintV("=== Verifying Calculated Hashes ===");
            VerifyHashes();

            Program.PrintV("=== Encrypting Methods ===");
            HandleEncryption();
            WriteToDisk(true, "temp_3.exe"); //when embedding resources, we need to write out 

            Program.PrintV("=== Stripping Method Data ===");
            StripEncryptedMethods();


            Program.PrintV("=== Writing to disk ===");
            WriteToDisk(false);


            Program.PrintV("=== Writing decryption key to disk ===");
            WriteKeyToDisk();
            return 0;
        }



        private void HandleHashes()
        {
            MD5 md5 = MD5.Create();
            foreach (HashableMethod method in Assembly.GetHashedMethods())//detect hash attribute methods
            {
                byte[] msil = method.GetMethodBytes(Assembly.Data);//read method msil bytes


                byte[] as_hash = md5.ComputeHash(msil);//md5 those bytes
                StringBuilder sb = new StringBuilder();

                for (int i = 0; i < as_hash.Length; i++)
                {
                    sb.Append(as_hash[i].ToString("X2"));
                }
                string hash = sb.ToString();

                method.Hash = hash;//replace attribute constructor argument with new md5

            }
        }
        private void WriteToDisk(bool temp = false, string file_name = "temp_asm.exe")
        {
            if(temp)
            {
                string file_path = WorkDirectory + "\\" + file_name;

                //use mono to write our assembly
                Assembly.Assembly.Write(file_path);

                this.Assembly = new ProtectableAssembly(file_path);//? why is this here
            }
            else
            {
                //write our bytes
                File.WriteAllBytes(output_file, this.Assembly.Data);
            }



        }
        private void WriteKeyToDisk()
        {
            try
            {
                File.WriteAllText(new FileInfo(output_file).Directory.FullName + @"\DECRYPTION.key", this.aes_key);

                Program.PrintV("Decryption Key written to disk");
            } catch
            {
            }
        }
        private void VerifyHashes()
        {
            MD5 md5 = MD5.Create();
            foreach (HashableMethod method in Assembly.GetHashedMethods())//detect hash attribute methods
            {
                byte[] msil = method.GetMethodBytes(Assembly.Data);//read method msil bytes


                byte[] as_hash = md5.ComputeHash(msil);//md5 those bytes
                StringBuilder sb = new StringBuilder();

                for (int i = 0; i < as_hash.Length; i++)
                {
                    sb.Append(as_hash[i].ToString("X2"));
                }
                string hash = sb.ToString();

                Program.PrintV($"\t\tCalculated Hash: {hash}");

                if (method.Hash != hash)
                {
                   throw new Exception("md5 does not match!");
                }
            }
        }
        private void HandleEncryption()
        {
            foreach(EncryptableMethod method in Assembly.GetEncryptedMethods())
            {
                byte[] msil = method.GetMethodBytes(Assembly.Data);//read method bytes
                byte[] encrypted;
                if(method.Type == Wrappers.EncryptionType.xor)
                {
                    encrypted = Encryption.Encryption.EncryptXOR(msil, XOR_BYTE);
                }
                else if(method.Type == Wrappers.EncryptionType.aes)
                {
                    encrypted = Encryption.Encryption.EncryptAES(msil, this.aes_key);
                }
                else
                {
                    throw new Exception("Unknown or incomplete encryption method.");
                }

                if(method.Streamed)
                {
                    #warning Using http for code streaming is insecure. We need a better solution
                    WebClient wc = new WebClient();
                    File.WriteAllBytes("src_" + method.Definition.Name, encrypted);
                    if (this.UPLOAD_URL == "")
                        this.UPLOAD_URL = "http://dev.lystic.net/netprotect/up.php";

                    wc.UploadFile(this.UPLOAD_URL, "src_" + method.Definition.Name);
                    File.Delete("src_" + method.Definition.Name);
                }
                else
                {
                    Program.PrintV($"\t\tEmbedding Resource: {method.Definition.Name} - {encrypted.Length} bytes");
                    Assembly.Assembly.MainModule.Resources.Add(new EmbeddedResource(method.Definition.Name, ManifestResourceAttributes.Public, encrypted));
                }

            }
        }


        private void StripEncryptedMethods()
        {
            foreach (EncryptableMethod method in Assembly.GetEncryptedMethods())
            {
                Assembly.StripMethodBytes(method);
            }
        }
    }
}
