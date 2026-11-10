namespace Vajra.WindowsAgent.Commands;

/// <summary>
/// Explicit allowlist matching backend ALLOWLISTED_DEVICE_ACTIONS.
/// Only REQUEST_DEVICE_STATUS is executed locally on Windows in this foundation.
/// </summary>
public static class CommandCapabilityMatrix
{
    public const string RequestDeviceStatus = "REQUEST_DEVICE_STATUS";
    public const string RequestLocation = "REQUEST_LOCATION";
    public const string RingDevice = "RING_DEVICE";
    public const string DisplayRecoveryMessage = "DISPLAY_RECOVERY_MESSAGE";
    public const string EnableLostMode = "ENABLE_LOST_MODE";
    public const string DisableLostMode = "DISABLE_LOST_MODE";

    public static bool IsKnown(string actionType) =>
        actionType is RequestDeviceStatus or RequestLocation or RingDevice
            or DisplayRecoveryMessage or EnableLostMode or DisableLostMode;

    /// <summary>True only when this agent version implements a safe local handler.</summary>
    public static bool IsExecutableOnWindows(string actionType) =>
        actionType == RequestDeviceStatus;

    public static string UnsupportedReason(string actionType) => actionType switch
    {
        RequestLocation => "Windows agent does not claim GPS/location in this version.",
        RingDevice => "Ring is not meaningful for a Windows PC in this agent version.",
        DisplayRecoveryMessage => "Desktop recovery UI not implemented in this agent version.",
        EnableLostMode or DisableLostMode => "Lost Mode is a server-side lifecycle action; Windows agent does not apply Android-style lock screens.",
        _ => "Action is not supported by this Windows agent.",
    };
}
