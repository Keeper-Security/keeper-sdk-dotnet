using System.Text;
using Authentication;

namespace Commander
{
    public static class CommanderExtensions
    {
        public static string BiometricCredentialTarget(this string username, byte[] token)
        {
            return $"Keeper.{username}.Bio.{token.TokenToString()}";
        }

        public static string TokenToString(this byte[] token)
        {
            var sb = new StringBuilder();
            foreach (var b in token)
            {
                sb.AppendFormat("{0:x2}", b);
                if (sb.Length >= 20)
                {
                    break;
                }
            }

            return sb.ToString();
        }

        public static string DeviceStatusToString(this DeviceStatus status)
        {
            switch (status)
            {
                case DeviceStatus.DeviceOk: return "OK";
                case DeviceStatus.DeviceNeedsApproval: return "Need Approval";
                case DeviceStatus.DeviceDisabledByUser: return "Disabled";
                case DeviceStatus.DeviceLockedByAdmin: return "Locked";
                default: return "";
            }
        }

    }
}
