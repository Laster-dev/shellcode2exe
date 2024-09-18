using AsmResolver;
using AsmResolver.PE.File;
using AsmResolver.PE.File.Headers;
using CommandLine;
using CommandLine.Text;
using System.Diagnostics.CodeAnalysis;
using System.Text;


namespace sc2pe
{
    internal class Program
    {
        public class Options
        {
            [Option('p', "path", Required = true, HelpText = "Path to shellcode file.")]
            public string? Path { get; set; }

            [Option('a', "architecture", Required = true, HelpText = "Architecture: 32 or 64 (depending on the shellcode).")]
            public uint? Architecture { get; set; }

            [Option('o', "offset", Required = false, Default = (uint)0, HelpText = "Optional. Start offset of the shellcode (default 0).")]
            public uint Offset { get; set; }

            [Usage(ApplicationAlias = "sc2pe")]
            public static IEnumerable<Example> Examples
            {
                get
                {
                    return new List<Example>()
                    {
                        new Example("Convert shellcode to 32-bit PE (shellcode Start Offset set to 66th byte)", new Options { Path = "C:\\64.bin", Architecture = 64, Offset = 0 })
                    };
                }
            }
        }
        static byte[] Combine(byte[] a1, byte[] a2)
        {
            byte[] ret = new byte[a1.Length + a2.Length];
            Array.Copy(a1, 0, ret, 0, a1.Length);
            Array.Copy(a2, 0, ret, a1.Length, a2.Length);
            return ret;
        }

        public static PEFile CreatePE(string path, uint epOffset, string[] funcPaths, bool is64Bit, ulong imageBase)
        {
            byte[] shellcode = new byte[10];
            var pe = new PEFile();
            var text = new PESection(".text", SectionFlags.MemoryExecute);
            var UPX0 = new PESection(".pdata", SectionFlags.MemoryRead | SectionFlags.MemoryWrite);
            var UPX1 = new PESection(".rdata", SectionFlags.MemoryRead | SectionFlags.MemoryWrite);

            foreach (var funcPath in funcPaths)
            {
                shellcode = Combine(shellcode, File.ReadAllBytes(funcPath));
            }
            epOffset += (uint)shellcode.Length;
            shellcode = Combine(shellcode, File.ReadAllBytes(path));
            foreach (var funcPath in funcPaths)
            {
                shellcode = Combine(shellcode, File.ReadAllBytes(funcPath));
            }
            text.Contents = new DataSegment(shellcode);
            UPX0.Contents = new DataSegment(Encoding.UTF8.GetBytes("This is a pdata"));
            UPX1.Contents = new DataSegment(Encoding.UTF8.GetBytes("This is a rdata"));

            pe.Sections.Add(text);
            pe.Sections.Add(UPX0);
            pe.Sections.Add(UPX1);

            if (is64Bit)
            {
                pe.OptionalHeader.ImageBase = imageBase;
                pe.FileHeader.Machine = MachineType.Amd64;
                pe.FileHeader.Characteristics = Characteristics.Image
                                                | Characteristics.LocalSymsStripped
                                                | Characteristics.LineNumsStripped
                                                | Characteristics.RelocsStripped
                                                | Characteristics.LargeAddressAware;
                pe.OptionalHeader.Magic = OptionalHeaderMagic.PE64;
                pe.OptionalHeader.SubSystem = SubSystem.WindowsGui;
                pe.OptionalHeader.DllCharacteristics = DllCharacteristics.DynamicBase
                                                       | DllCharacteristics.NxCompat
                                                       | DllCharacteristics.TerminalServerAware;
            }
            else
            {
                pe.OptionalHeader.ImageBase = imageBase;
                pe.FileHeader.Machine = MachineType.I386;
                pe.FileHeader.Characteristics = Characteristics.Image
                                                | Characteristics.LocalSymsStripped
                                                | Characteristics.LineNumsStripped
                                                | Characteristics.RelocsStripped
                                                | Characteristics.Machine32Bit;
                pe.OptionalHeader.Magic = OptionalHeaderMagic.PE32;
                pe.OptionalHeader.SubSystem = SubSystem.WindowsGui;
                pe.OptionalHeader.DllCharacteristics = DllCharacteristics.DynamicBase
                                                       | DllCharacteristics.NxCompat
                                                       | DllCharacteristics.TerminalServerAware;
            }

            pe.UpdateHeaders();
            pe.OptionalHeader.AddressOfEntryPoint = text.Rva + epOffset;

            return pe;
        }

        static string[] GetRandomFiles(string folderPath, int count)
        {
            string[] allFiles = Directory.GetFiles(folderPath);
            Random rng = new Random();
            return allFiles.OrderBy(x => rng.Next()).Take(count).ToArray();
        }
        [DynamicDependency(DynamicallyAccessedMemberTypes.All, typeof(Options))]
        static void Main(string[] args)
        {
            Parser.Default.ParseArguments<Options>(args)
                   .WithParsed<Options>(o =>
                   {
                       if (!File.Exists(o.Path)) { Console.WriteLine($"Can´t find shellcode file: {o.Path}"); }
                       else
                       {
                           long fileSize = new System.IO.FileInfo(o.Path).Length;
                           string folderPath = @".\text"; // 指定文件夹路径
                           int numberOfFilesToSelect = 2; // 指定要抽取的文件数量

                           string[] selectedFiles = GetRandomFiles(folderPath, numberOfFilesToSelect);

                           // 打印选中的文件路径
                           foreach (var file in selectedFiles)
                           {
                               Console.WriteLine(file);
                           }

                           bool is64Bit = o.Architecture == 64;
                           ulong imageBase = is64Bit ? (ulong)0x140000000 : (ulong)0x40000000;
                           var pe = CreatePE(o.Path, o.Offset, selectedFiles, is64Bit, imageBase);
                           pe.Write(o.Path + ".exe");
                           Console.WriteLine($"PE created: {o.Path + ".exe"}");
                       }
                   });
        }

    }
}
