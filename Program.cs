using CommandLine;
using NetProtectEncrypter.CommandLine;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NetProtectEncrypter
{
    class Program
    {
        static readonly int EXIT_INPUT_FAILED = 1;


        public static void PrintV(string message)
        {
            if (!Verbose_Output) return;


            Console.WriteLine(message);
        }


        static bool Verbose_Output = false;
        static void Main(string[] args)
        {
            Console.Title = "NetProtect Encrypter";

            bool parse_failed = false;
            string input_file = "";
            string output_file = "";
            string aes_key = "";
            string upload_url = "";

            //parse arguments
            Parser parser = Parser.Default;
            ParserResult<Options> result = parser.ParseArguments<Options>(args);
            result = result.WithParsed(options =>
            {
                Verbose_Output = options.Verbose;
                input_file = options.File;
                output_file = options.Output;
                aes_key = options.Key;
                upload_url = options.Url;
            });
            result.WithNotParsed(errors =>
            {
                foreach (Error error in errors)
                {
                    if (error.Tag == ErrorType.MissingRequiredOptionError)
                    {
                        parse_failed = true;
                    }
                }
            });

            if(parse_failed)
            {
                Environment.Exit(EXIT_INPUT_FAILED);
            }

            Console.WriteLine("Encrypting...");
            Encrypter.NetProtect protector = new Encrypter.NetProtect(input_file, output_file, aes_key,upload_url);
            int exit_code = protector.ProtectAssembly();

            Environment.Exit(exit_code);
        }
    }
}
