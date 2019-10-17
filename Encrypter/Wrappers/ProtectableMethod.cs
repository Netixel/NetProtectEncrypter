using Mono.Cecil;
using PeNet;
using PeNet.Structures;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NetProtectEncrypter.Encrypter.Wrappers
{
    enum EncryptionType
    {
        xor,
        aes,
        rsa
    }

    class ProtectableMethod
    {
        public MethodDefinition Definition { get; }
        public IMAGE_SECTION_HEADER Header { get; }
        public ProtectableMethod(MethodDefinition method, IMAGE_SECTION_HEADER section)
        {
            Definition = method;
            Header = section;
        }

        public uint GetFileOffset()
        {
            uint RVA = (uint)Definition.RVA;
            uint RawOffset = Header.PointerToRawData;
            uint VirtualOffset = Header.VirtualAddress;

            uint file_offset = RVA - VirtualOffset + RawOffset;
            return file_offset;
        }
        public uint GetCodeOffset(byte[] file_bytes)
        {
            return GetFileOffset() + GetHeaderSize(file_bytes);

        }
        public uint GetHeaderSize(byte[] file_bytes)
        {

            byte first_byte = file_bytes[GetFileOffset()];

            byte fat_header = 0x3; //fat header 11

            if ((first_byte & fat_header) == fat_header)
            {
                Program.PrintV($"\t\tHeader Size: FAT");
                return 12;
            }
            else
            {
                Program.PrintV($"\t\tHeader Size: TINY");
                return 1;
            }
        }

        public byte[] GetMethodBytes(byte[] AsmBytes)
        {
            byte[] data = AsmBytes.ToList().GetRange((int)GetCodeOffset(AsmBytes), Definition.Body.CodeSize).ToArray();
            Program.PrintV($"\t\tBytes: {BitConverter.ToString(data)}");
            return data;
        }
    }

    class HashableMethod : ProtectableMethod
    {
        public string Hash {
            get {
                CustomAttribute hash_attribute = Definition.CustomAttributes.Where((ca) =>
                {
                    return ca.AttributeType.Name.Contains("MethodHash");
                }).ElementAt(0);
                string result = (string)hash_attribute.ConstructorArguments[0].Value;
                Program.PrintV($"\t\tCurrent Hash: {result}");
                return result;
            }
            set {

                CustomAttribute current_attribute = Definition.CustomAttributes.Where((ca) =>
                {
                    return ca.AttributeType.Name.Contains("MethodHash");
                }).ElementAt(0);

                Program.PrintV($"\t\tSetting Hash: {value}");
                //testing - replace constructor argument
                TypeReference string_ref = current_attribute.ConstructorArguments[0].Type;
                current_attribute.ConstructorArguments[0] = new CustomAttributeArgument(string_ref, value);
            }
        }


        public HashableMethod(MethodDefinition method, IMAGE_SECTION_HEADER section) : base(method, section)
        {

        }

    }

    class EncryptableMethod : ProtectableMethod
    {


        public EncryptionType Type {
            get {
                CustomAttribute hash_attribute = Definition.CustomAttributes.Where((ca) =>
                {
                    return ca.AttributeType.Name.Contains("ClrEncrypted");
                }).ElementAt(0);
                EncryptionType result = (EncryptionType)hash_attribute.ConstructorArguments[0].Value;
                Program.PrintV($"\t\tEncryption Type: {Enum.GetName(typeof(EncryptionType),result)}");
                return result;
            }
        }
        public bool Streamed {
            get {
                CustomAttribute hash_attribute = Definition.CustomAttributes.Where((ca) =>
                {
                    return ca.AttributeType.Name.Contains("ClrEncrypted");
                }).ElementAt(0);
                bool result = (bool)hash_attribute.ConstructorArguments[1].Value;
                Program.PrintV($"\t\tStreamed?: {(result ? "Yes" : "No")}");
                return result;
            }
        }

        public EncryptableMethod(MethodDefinition method, IMAGE_SECTION_HEADER section) : base(method, section)
        {

        }
    }
}
