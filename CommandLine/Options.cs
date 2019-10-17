using CommandLine;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NetProtectEncrypter.CommandLine
{
    class Options
    {
        [Option('v', "verbose", Required = false, HelpText = "Verbose output")]
        public bool Verbose { get; set; }

        [Option('f', "file", Required = true, HelpText = ".NET assembly to encrypt")]
        public string File { get; set; }

        [Option('o', "output", Required = true, HelpText = "Output file name")]
        public string Output { get; set; }

        [Option('k', "key", Required = true, HelpText = "AES Encryption Key")]
        public string Key { get; set; }

        [Option('u', "url", Required = true, HelpText = "Remote Upload URL")]
        public string Url { get; set; }
    }
}
