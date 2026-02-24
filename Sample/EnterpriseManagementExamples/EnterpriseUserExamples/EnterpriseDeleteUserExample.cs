using System;
using System.Threading.Tasks;
using KeeperSecurity.Enterprise;
using KeeperSecurity.Authentication;
using Sample.Helpers;

namespace Sample.EnterpriseManagementExamples.EnterpriseUserExamples
{
    public static class EnterpriseDeleteUserExample
    {
        public static async Task DeleteUser(string email)
        {
            var vault = await AuthenticateAndGetVault.GetVault();

            if (vault == null)
            {
                Console.WriteLine("Authentication failed. Vault is null.");
                return;
            }
            if (!EnterpriseHelper.RequireEnterpriseAdmin(vault))
            {
                return;
            }
            if (string.IsNullOrWhiteSpace(email))
            {
                Console.WriteLine("Email is required.");
                return;
            }

            var enterpriseData = new EnterpriseData();
            var enterpriseLoader = new EnterpriseLoader(
                vault.Auth,
                new EnterpriseDataPlugin[] { enterpriseData });
            await enterpriseLoader.Load();

            if (!enterpriseData.TryGetUserByEmail(email, out var user))
            {
                Console.WriteLine($"User {email} not found.");
                return;
            }
            else
            {
                await enterpriseData.DeleteUser(user);
                Console.WriteLine($"User {email} deleted successfully.");
            }
        }
    }
}