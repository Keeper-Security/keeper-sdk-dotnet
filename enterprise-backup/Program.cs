using System.Threading.Tasks;
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

        static void Main()
        {
            ;
            var mainLoop = new MainLoop
            {
                StateContext = new MainMenuCliContext()
            };
            Task.WaitAny(Task.Run(() => { InputManager.Run(); }), mainLoop.Run());
        }
    }
}
