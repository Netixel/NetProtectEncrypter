using Mono.Cecil;
using Mono.Collections.Generic;
using NetProtectEncrypter.Encrypter.Wrappers;
using PeNet;
using PeNet.Structures;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NetProtectEncrypter.Encrypter
{
    class ProtectableAssembly
    {
        public AssemblyDefinition Assembly;
        public byte[] Data;
        public PeFile PE;

        public ProtectableAssembly(string file_path)
        {
            this.Data = File.ReadAllBytes(file_path);
            this.Assembly = AssemblyDefinition.ReadAssembly(file_path);
            this.PE = new PeFile(file_path);
        }

        public void StripMethodBytes(ProtectableMethod method)
        {
            Program.PrintV($"\t\tStripping method: {method.Definition.Name}");
            int offset = (int)method.GetCodeOffset(this.Data);
            bool writeonce = false;


            int length = method.Definition.Body.CodeSize;

            int start = offset;
            int stop = offset + length;

            for (int i = stop-1; i >= start; i--)
            {
                if (!writeonce)
                    this.Data[i] = 0x2A;
                else
                    this.Data[i] = 0x1;

                writeonce = true;
            }
        }


        public IEnumerable<HashableMethod> GetHashedMethods()
        {
            Program.PrintV("Finding hashed methods...");

            ModuleDefinition main_module = Assembly.MainModule;
            Collection<TypeDefinition> types = main_module.Types;
            foreach (TypeDefinition type in types)
            {
                Collection<MethodDefinition> methods = type.Methods;
                foreach (MethodDefinition method in methods)
                {
                    if (method.HasBody && method.HasCustomAttributes)
                    {
                        foreach (CustomAttribute attribute in method.CustomAttributes)
                        {
                            if (attribute.AttributeType.Name.Contains("MethodHash"))
                            {
                                Program.PrintV($"\tMethod: {method.Name}");
                                yield return new HashableMethod(method, GetMethodSection(method));
                            }
                        }
                    }
                }
            }
        }

        public IEnumerable<EncryptableMethod> GetEncryptedMethods()
        {
            Program.PrintV("Finding encrypted methods...");
            ModuleDefinition main_module = Assembly.MainModule;
            Collection<TypeDefinition> types = main_module.Types;
            foreach (TypeDefinition type in types)
            {
                Collection<MethodDefinition> methods = type.Methods;
                foreach (MethodDefinition method in methods)
                {
                    if (method.HasBody && method.HasCustomAttributes)
                    {
                        foreach (CustomAttribute attribute in method.CustomAttributes)
                        {
                            if (attribute.AttributeType.Name.Contains("ClrEncrypted"))
                            {
                                Program.PrintV($"\tMethod: {method.Name}");
                                yield return new EncryptableMethod(method, GetMethodSection(method));
                            }
                        }
                    }
                }
            }
        }

        private IMAGE_SECTION_HEADER GetMethodSection(MethodDefinition method)
        {
            uint RVA = (uint)method.RVA;
            for (int i = 0; i < PE.ImageSectionHeaders.Length; i++)
            {
                var section = PE.ImageSectionHeaders[i];
                uint raw_offset = section.PointerToRawData;
                uint virtual_offset = section.VirtualAddress;
                if (virtual_offset > RVA)
                {
                    i--;
                    if (i == -1)
                        throw new Exception("Method section less than first section");

                    return PE.ImageSectionHeaders[i];
                }
                //if its the largest possible section
                if (i == PE.ImageSectionHeaders.Length - 1)
                {
                    return PE.ImageSectionHeaders[i];
                }
            }
            return null;
        }
    }
}
