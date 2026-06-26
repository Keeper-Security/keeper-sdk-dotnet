using System;
using KeeperSecurity.Authentication;

namespace KeeperSecurity.Plugins.PAM
{
  /// <summary>
  /// Base exception for PAM operations.
  /// </summary>
  public class PamException : Exception
  {
    public PamException(string message) : base(message) { }

    public PamException(string message, Exception innerException) : base(message, innerException) { }
  }

  /// <summary>
  /// PAM plugin is unavailable or cannot be initialized.
  /// </summary>
  public class PamPluginException : PamException
  {
    public PamPluginException(string message) : base(message) { }

    public PamPluginException(string message, Exception innerException) : base(message, innerException) { }
  }

  /// <summary>
  /// Gateway operation failed.
  /// </summary>
  public class PamGatewayException : PamException
  {
    public PamGatewayException(string message) : base(message) { }

    public PamGatewayException(string message, Exception innerException) : base(message, innerException) { }
  }

  /// <summary>
  /// Gateway was not found.
  /// </summary>
  public class PamGatewayNotFoundException : PamGatewayException
  {
    public PamGatewayNotFoundException(string identifier) : base($"Gateway '{identifier}' not found")
    {
      Identifier = identifier;
    }

    public string Identifier { get; }
  }

  /// <summary>
  /// Multiple gateways match the given identifier.
  /// </summary>
  public class PamGatewayAmbiguousException : PamGatewayException
  {
    public PamGatewayAmbiguousException(string identifier)
      : base($"Multiple gateways match name \"{identifier}\". Please specify Gateway UID.")
    {
      Identifier = identifier;
    }

    public string Identifier { get; }
  }

  /// <summary>
  /// KSM application was not found.
  /// </summary>
  public class PamApplicationNotFoundException : PamGatewayException
  {
    public PamApplicationNotFoundException(string identifier) : base($"KSM application '{identifier}' not found")
    {
      Identifier = identifier;
    }

    public string Identifier { get; }
  }

  /// <summary>
  /// PAM JSON API error.
  /// </summary>
  public class PamApiException : KeeperApiException
  {
    public PamApiException(string code, string message) : base(code, message) { }
  }

  /// <summary>
  /// PAM router is unavailable.
  /// </summary>
  public class PamRouterException : PamException
  {
    public PamRouterException(string message) : base(message) { }

    public PamRouterException(string message, Exception innerException) : base(message, innerException) { }
  }
}
