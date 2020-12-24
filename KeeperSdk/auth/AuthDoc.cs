//  _  __
// | |/ /___ ___ _ __  ___ _ _ ®
// | ' </ -_) -_) '_ \/ -_) '_|
// |_|\_\___\___| .__/\___|_|
//              |_|
//
// Keeper SDK
// Copyright 2020 Keeper Security Inc.
// Contact: ops@keepersecurity.com
//

using System.Runtime.CompilerServices;

namespace KeeperSecurity.Authentication
{
    /// <summary>
    ///     Provides base types for establishing connection to Keeper servers.
    /// </summary>
    /// <seealso cref="Async.Auth"/>
    /// <seealso cref="Sync.AuthSync"/>
    [CompilerGenerated]
    internal class NamespaceDoc
    {
    }

    namespace Sync
    {
        /// <summary>
        ///     Provides types for connecting to Keeper servers (sync).
        /// </summary>
        [CompilerGenerated]
        internal class NamespaceDoc
        {
        }
    }

    namespace Async
    {
        /// <summary>
        ///     Provides types for connecting to Keeper servers (async).
        /// </summary>
        /// <example>
        ///     This example shows how to authenticate at Keeper server.
        ///     <code>
        /// using System.Linq;
        /// using System.Threading;
        /// using System.Threading.Tasks;
        /// using KeeperSecurity.Authentication;
        /// using KeeperSecurity.Authentication.Async;
        /// using KeeperSecurity.Configuration;
        /// 
        /// class AuthUi : IAuthUI
        /// {
        ///     public Task&lt;bool&gt; WaitForDeviceApproval(IDeviceApprovalChannelInfo[] channels, CancellationToken token)
        ///     {
        ///         // find email device approval channel.
        ///         var emailChannel = channels
        ///             .Cast&lt;IDeviceApprovalPushInfo&gt;()
        ///             .FirstOrDefault(x => x.Channel == DeviceApprovalChannel.Email);
        ///         if (emailChannel != null)
        ///         {
        ///             // invoke send email action.
        ///             _ = Task.Run(async () =>
        ///             {
        ///                 await emailChannel.InvokeDeviceApprovalPushAction();
        ///             });
        ///         }
        ///         return new TaskCompletionSource&lt;bool&gt;().Task;
        ///     }
        ///     public async Task&lt;bool&gt; WaitForTwoFactorCode(ITwoFactorChannelInfo[] channels, CancellationToken token)
        ///     {
        ///         // find 2FA code channel.
        ///         var codeChannel = channels
        ///             .Cast&lt;ITwoFactorAppCodeInfo&gt;()
        ///             .FirstOrDefault();
        ///         if (codeChannel != null)
        ///         {
        ///             Console.WriteLine("Enter 2FA code: ");
        ///             var code = Console.ReadLine();
        ///             await codeChannel.InvokeTwoFactorCodeAction("code");
        ///             return true;
        ///         }
        ///         return false;
        ///     }
        ///     public async Task&lt;bool&gt; WaitForUserPassword(IPasswordInfo info, CancellationToken token)
        ///     {
        ///         Console.WriteLine($"Enter password for {info.Username}: ");
        ///         var password = Console.ReadLine();
        ///         await info.InvokePasswordActionDelegate(password);
        ///         return true;
        ///     }
        /// }
        /// 
        /// internal static class Program
        /// {
        ///     private static async Task Main()
        ///     {
        ///         var auth = new Auth(new AuthUi(), new JsonConfigurationStorage());
        ///         await auth.Login("username@company.com");
        ///     }
        /// }
        /// </code>
        /// </example>
        /// <seealso cref="IAuth" />
        /// <seealso cref="IAuthUI" />
        /// <seealso cref="Configuration.JsonConfigurationStorage" />
        [CompilerGenerated]
        internal class NamespaceDoc
        {
        }
    }
}
