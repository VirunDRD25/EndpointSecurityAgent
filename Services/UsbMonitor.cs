using System.Collections.Concurrent;
using System.Management;
using EndpointSecurityAgent.Models;
using Microsoft.Extensions.Logging;

namespace EndpointSecurityAgent.Services;

/// <summary>
/// Subscribes to WMI Win32_VolumeChangeEvent to detect when a removable
/// (USB) drive is inserted or removed, without polling. When a drive is
/// inserted, it also triggers FileDownloadMonitor to start watching that
/// drive's root for new executables (covers the "USB -> copies malware" path).
/// </summary>
public class UsbMonitor : IDisposable
{
    private readonly ILogger<UsbMonitor> _logger;
    private readonly FileDownloadMonitor _fileDownloadMonitor;
    private readonly ConcurrentQueue<UsbEvent> _pendingEvents = new();
    private ManagementEventWatcher? _insertWatcher;
    private ManagementEventWatcher? _removeWatcher;

    // EventType per WMI docs: 2 = drive inserted (arrival), 3 = drive removed
    private const int VolumeInserted = 2;
    private const int VolumeRemoved = 3;

    public UsbMonitor(ILogger<UsbMonitor> logger, FileDownloadMonitor fileDownloadMonitor)
    {
        _logger = logger;
        _fileDownloadMonitor = fileDownloadMonitor;
    }

    public void Start()
    {
        try
        {
            var query = new WqlEventQuery("SELECT * FROM Win32_VolumeChangeEvent WHERE EventType = 2 OR EventType = 3");
            var scope = new ManagementScope(@"root\CIMV2");
            _insertWatcher = new ManagementEventWatcher(scope, query);
            _insertWatcher.EventArrived += OnVolumeChangeEvent;
            _insertWatcher.Start();

            _logger.LogInformation("USB / removable drive monitoring started");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to start USB monitoring via WMI event watcher");
        }
    }

    private void OnVolumeChangeEvent(object sender, EventArrivedEventArgs e)
    {
        try
        {
            var eventType = Convert.ToInt32(e.NewEvent["EventType"]);
            var driveLetter = e.NewEvent["DriveName"]?.ToString() ?? "Unknown";

            if (eventType == VolumeInserted)
            {
                var description = GetDriveDescription(driveLetter);
                var usbEvent = new UsbEvent
                {
                    DeviceDescription = description,
                    DriveLetter = driveLetter,
                    InsertedUtc = DateTime.UtcNow,
                    EventType = "Inserted"
                };

                _pendingEvents.Enqueue(usbEvent);
                _logger.LogInformation("USB drive inserted: {Drive} ({Description})", driveLetter, description);

                // Start scanning the new drive root for dropped executables.
                _fileDownloadMonitor.WatchDrive(driveLetter);
            }
            else if (eventType == VolumeRemoved)
            {
                _pendingEvents.Enqueue(new UsbEvent
                {
                    DeviceDescription = "Removable drive",
                    DriveLetter = driveLetter,
                    InsertedUtc = DateTime.UtcNow,
                    EventType = "Removed"
                });
                _logger.LogInformation("USB drive removed: {Drive}", driveLetter);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error handling volume change event");
        }
    }

    private string GetDriveDescription(string driveLetter)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                $"SELECT VolumeName, FileSystem FROM Win32_LogicalDisk WHERE DeviceID = '{driveLetter}' AND DriveType = 2");

            foreach (ManagementObject obj in searcher.Get())
            {
                var name = obj["VolumeName"]?.ToString();
                return string.IsNullOrWhiteSpace(name) ? "USB Storage Device" : name;
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Could not resolve friendly name for {Drive}", driveLetter);
        }

        return "USB Storage Device";
    }

    public List<UsbEvent> DrainPendingEvents()
    {
        var list = new List<UsbEvent>();
        while (_pendingEvents.TryDequeue(out var item)) list.Add(item);
        return list;
    }

    public void Dispose()
    {
        _insertWatcher?.Stop();
        _insertWatcher?.Dispose();
        _removeWatcher?.Stop();
        _removeWatcher?.Dispose();
    }
}
