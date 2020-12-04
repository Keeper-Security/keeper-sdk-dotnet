using System;
using KeeperSecurity.Utils;

namespace EnterpriseBackup
{
    internal class Program
    {
        private static readonly InputManager InputManager = new InputManager();

        public static InputManager GetInputManager()
        {
            return InputManager;
        }

        static void Welcome()
        {
            Console.WriteLine();
            Console.WriteLine(@" _  __                      ");
            Console.WriteLine(@"| |/ /___ ___ _ __  ___ _ _ ");
            Console.WriteLine(@"| ' </ -_) -_) '_ \/ -_) '_|");
            Console.WriteLine(@"|_|\_\___\___| .__/\___|_|  ");
            Console.WriteLine(@"             |_|            ");
            Console.WriteLine(@"password manager & digital vault");
            Console.WriteLine();
            Console.WriteLine("Type \"?\" for command help");
            Console.WriteLine();
        }
        static void Main()
        {
            Console.Clear();
            Console.SetCursorPosition(0, 0);
            Welcome();

            var mainLoop = new MainLoop
            {
                StateContext = new MainMenuCliContext()
            };

            _ = mainLoop.Run();
            InputManager.Run();
        }
    }
}
