using System;
using System.Linq;
using System.Threading.Tasks;
using Cli;
using KeeperSecurity.Authentication;
using KeeperSecurity.Utils;

namespace Commander
{
    internal sealed class CommanderPostLoginTaskUI : IPostLoginTaskUI, IMasterPasswordStrengthUI
    {
        private readonly IInputManager _inputManager;

        public CommanderPostLoginTaskUI(IInputManager inputManager)
        {
            _inputManager = inputManager ?? throw new ArgumentNullException(nameof(inputManager));
        }

        public async Task<bool> Confirmation(string information)
        {
            Console.WriteLine(information);
            Console.Write("Continue? (y/N): ");
            var response = await _inputManager.ReadLine(new ReadLineParameters { IsHistory = false });
            return string.Equals(response?.Trim(), "y", StringComparison.OrdinalIgnoreCase)
                || string.Equals(response?.Trim(), "yes", StringComparison.OrdinalIgnoreCase);
        }

        public async Task<string> GetNewPassword(PasswordRuleMatcher matcher)
        {
            while (true)
            {
                Console.Write("Enter new Master Password: ");
                var password = await _inputManager.ReadLine(new ReadLineParameters
                {
                    IsSecured = true,
                    IsHistory = false,
                });

                Console.Write("Re-enter new Master Password: ");
                var confirmation = await _inputManager.ReadLine(new ReadLineParameters
                {
                    IsSecured = true,
                    IsHistory = false,
                });

                if (string.IsNullOrEmpty(password))
                {
                    Console.WriteLine("Master Password cannot be empty.");
                    continue;
                }

                if (!string.Equals(password, confirmation, StringComparison.Ordinal))
                {
                    Console.WriteLine("New password does not match. Please try again.");
                    continue;
                }

                var failedRules = matcher?.MatchFailedRules(password) ?? Array.Empty<string>();
                if (failedRules.Length > 0)
                {
                    Console.WriteLine("Password rules:");
                    foreach (var failedRule in failedRules.Distinct())
                    {
                        Console.WriteLine($"  {failedRule}");
                    }

                    continue;
                }

                return password;
            }
        }

        public Task ReportMasterPasswordStrength(int score, string category)
        {
            Console.WriteLine(string.Equals(category, "UNKNOWN", StringComparison.OrdinalIgnoreCase)
                ? "Password strength could not be determined."
                : $"Password strength: {category}");
            return Task.CompletedTask;
        }
    }
}
