using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;

namespace Cli
{
    public static class Utils
    {
        public static void Welcome()
        {
            string version = null;
            string product = null;
            try
            {
                var fileName = Process.GetCurrentProcess().MainModule?.FileName;
                if (!string.IsNullOrEmpty(fileName))
                {
                    var executable = Path.GetFileNameWithoutExtension(fileName);
                    if (!string.Equals(executable, "dotnet"))
                    {
                        var ver = FileVersionInfo.GetVersionInfo(fileName);
                        if (ver.ProductMajorPart > 0)
                        {
                            version = $"{ver.ProductMajorPart}.{ver.ProductMinorPart}.{ver.ProductBuildPart}";
                            product = ver.ProductName;
                        }
                    }
                }
            }
            catch { /*ignored*/ }

            if (string.IsNullOrEmpty(version))
            {
                try
                {
                    version = Assembly.GetEntryAssembly()?.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
                    product = Assembly.GetEntryAssembly()?.GetCustomAttribute<AssemblyProductAttribute>()?.Product;
                }
                catch { /*ignored*/ }
            }
            if (!string.IsNullOrEmpty(version))
            {
                version = "v" + version;
            }

            // https://stackoverflow.com/questions/30418886/how-and-why-does-quickedit-mode-in-command-prompt-freeze-applications
            // https://stackoverflow.com/questions/13656846/how-to-programmatic-disable-c-sharp-console-applications-quick-edit-mode
            // Application freezes on start up eventually.
            Console.WriteLine();
            Console.WriteLine(@" _  __                      ");
            Console.WriteLine(@"| |/ /___ ___ _ __  ___ _ _ ");
            Console.WriteLine(@"| ' </ -_) -_) '_ \/ -_) '_|");
            Console.WriteLine(@"|_|\_\___\___| .__/\___|_|  ");
            Console.WriteLine(@"             |_|            ");
            Console.WriteLine(@"password manager & digital vault");
            Console.WriteLine($"{product ?? ""} {version ?? ""}");
            Console.WriteLine();
            Console.WriteLine("Type \"?\" for command help");
            Console.WriteLine();
        }
    }
}
