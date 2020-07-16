using System;
using System.Threading.Tasks;
using KeeperSecurity.Sdk;
using KeeperSecurity.Sdk.UI;

namespace Tests
{
    public static class TestUtils
    {
        public static Func<Task<TwoFactorCode>> GetTwoFactorCodeHandler(TwoFactorDuration duration, params string[] codes)
        {
            var pos = 0;
            return () =>
            {
                if (pos < codes.Length)
                {
                    var code = codes[pos];
                    pos++;
                    return Task.FromResult(new TwoFactorCode(TwoFactorChannel.Authenticator, code, duration));
                }

                return Task.FromException<TwoFactorCode>(new KeeperCanceled());
            };
        }


    }
}
