using System;
using Authentication;

namespace KeeperSecurity.Authentication
{
    /// <exclude/>
    public class KeeperInvalidParameter : Exception
    {
        public KeeperInvalidParameter(string method, string parameter, string value, string message) : base(message)
        {
            Method = method;
            Parameter = parameter;
            Value = value;
        }

        public string Method { get; }
        public string Parameter { get; }
        public string Value { get; }
    }

    /// <summary>
    /// User is not allowed to login.
    /// </summary>
    public class KeeperPostLoginErrors : KeeperApiException
    {
        public KeeperPostLoginErrors(string code, string message) : base(code, message)
        {
        }
    }

    /// <summary>
    /// Keeper JSON API error.
    /// </summary>
    public class KeeperApiException : Exception
    {
        internal KeeperApiException(string code, string message) : base(message)
        {
            Code = code;
        }

        /// <summary>
        /// Error code.
        /// </summary>
        public string Code { get; }
    }

    /// <exclude />
    public class KeeperRegionRedirect : Exception
    {
        public KeeperRegionRedirect(string regionHost)
        {
            RegionHost = regionHost;
        }

        public string Username { get; set; }
        public string RegionHost { get; set; }
    }

    /// <exclude />
    public class KeeperInvalidDeviceToken : Exception
    {
        public string AdditionalInfo { get; }

        public KeeperInvalidDeviceToken(string additionalInfo)
        {
            AdditionalInfo = additionalInfo;
        }
    }

    /// <summary>
    /// Login is cancelled exception.
    /// </summary>
    public class KeeperCanceled : Exception
    {
    }

    /// <summary>
    /// Authentication failed exception.
    /// </summary>
    public class KeeperAuthFailed : Exception
    {
        public KeeperAuthFailed(string message) : base(message)
        {
        }
    }

    /// <summary>
    /// Unrecoverable error occurred during login.
    /// </summary>
    public class KeeperStartLoginException : Exception
    {
        /// <summary>
        /// Login state triggered exception.
        /// </summary>
        public LoginState LoginState { get; }

        internal KeeperStartLoginException(LoginState loginState, string message) 
            : base(string.IsNullOrEmpty(message) ? loginState.ToString() : message)
        {
            LoginState = loginState;
        }
    }
}