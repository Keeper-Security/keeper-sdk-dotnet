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

  /// <summary>
  /// PAM gateway action (rotate / job-info) failed.
  /// </summary>
  public class PamActionException : PamException
  {
    public PamActionException(string message) : base(message) { }

    public PamActionException(string message, Exception innerException) : base(message, innerException) { }
  }

  /// <summary>
  /// Rotation is blocked by enterprise enforcement.
  /// </summary>
  public class PamRotationNotAllowedException : PamActionException
  {
    public PamRotationNotAllowedException()
      : base("Rotation is not allowed for this account by enterprise enforcement (allow_rotate_credentials).")
    {
    }
  }

  /// <summary>
  /// Thrown when PAM interactive connection setup fails.
  /// </summary>
  public class PamConnectionException : PamException
  {
    public PamConnectionException(string message) : base(message) { }

    public PamConnectionException(string message, Exception innerException) : base(message, innerException) { }
  }

  /// <summary>
  /// Thrown when Remote Browser Isolation (RBI) setup or launch fails.
  /// </summary>
  public class PamRbiException : PamException
  {
    public PamRbiException(string message) : base(message) { }

    public PamRbiException(string message, Exception innerException) : base(message, innerException) { }
  }

  /// <summary>
  /// Thrown when PAM session launch preflight checks fail.
  /// </summary>
  public class PamLaunchException : PamException
  {
    public PamLaunchException(string message) : base(message) { }

    public PamLaunchException(string message, Exception innerException) : base(message, innerException) { }
  }
}
