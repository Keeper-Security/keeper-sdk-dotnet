using System;
using Authentication;

namespace KeeperSecurity.Authentication
{
    /// <exclude/>
    public class ProxyAuthenticationRequired : Exception
    {
        public ProxyAuthenticationRequired(string[] proxyAuthenticate)
        {
            ProxyAuthenticate = proxyAuthenticate;
        }
        public string[] ProxyAuthenticate { get; }
    }

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

    /// <exclude />
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
        /// <summary>
        /// Creates KeeperApiException
        /// </summary>
        /// <param name="code">Kepper Error Code</param>
        /// <param name="message">Error Message</param>
        public KeeperApiException(string code, string message) : base(message)
        {
            Code = code;
        }

        /// <summary>
        /// Error code.
        /// </summary>
        public string Code { get; }
    }

    /// <summary>
    /// Shared helpers for classifying Keeper API / router exceptions.
    /// </summary>
    public static class KeeperExceptionExtensions
    {
        /// <summary>
        /// Returns true when the exception (or an inner exception) indicates API or HTTP 429 throttling.
        /// </summary>
        public static bool IsThrottleError(this Exception ex)
        {
            if (ex == null)
            {
                return false;
            }

            if (ex is KeeperApiException api)
            {
                if (string.Equals(api.Code, "throttled", StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }

                // ExecuteRouterRest uses code "router_error" and message "...: {statusCode}".
                if (string.Equals(api.Code, "router_error", StringComparison.OrdinalIgnoreCase)
                    && api.Message != null
                    && api.Message.EndsWith(": 429", StringComparison.Ordinal))
                {
                    return true;
                }
            }

            if (ex.Message != null
                && ex.Message.IndexOf("throttl", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return true;
            }

            return ex.InnerException != null && IsThrottleError(ex.InnerException);
        }
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
        public KeeperInvalidDeviceToken(string additionalInfo) : base(additionalInfo)
        {
        }
    }

    /// <summary>
    /// Login is cancelled exception.
    /// </summary>
    public class KeeperCanceled : Exception
    {
        public KeeperCanceled() : this("canceled", "Login session is canceled. Please start over.") { }
        public string Reason { get; }
        public KeeperCanceled(string reason, string message) : base(message) {
            Reason = reason;
        }
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