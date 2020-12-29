using System;
using System.IO;
using Cli;
using KeeperSecurity.Configuration;
using KeeperSecurity.Utils;

namespace ClientTester
{
    class Program
    {
        private static readonly InputManager InputManager = new InputManager();

        public static InputManager GetInputManager()
        {
            return InputManager;
        }

        public static void EnqueueCommand(string command)
        {
            _mainLoop.CommandQueue.Enqueue(command);
        }

        public static JsonConfigurationStorage Storage { get; set; }


        private static MainLoop _mainLoop = new MainLoop();
        static void Main()
        {
            Console.Clear();
            Console.SetCursorPosition(0, 0);
            Utils.Welcome();

            Storage = new JsonConfigurationStorage();

            _mainLoop.StateContext = new NotConnectedCommands();
            _ = _mainLoop.Run(GetInputManager());
            InputManager.Run();
        }
    }
}
