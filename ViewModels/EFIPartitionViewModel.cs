using System;
using Avalonia.Media;
using ReactiveUI;
using SelfSecureBoot.Core;

namespace SelfSecureBoot.ViewModels;

public sealed class EFIPartitionViewModel : ReactiveObject
{
    public EFIPartition Partition { get; }

    public string Id => Partition.Id;
    public string VolumeName => Partition.VolumeName;
    public string DiskName => Partition.DiskName;
    public string? MountPoint => Partition.MountPoint;
    public bool IsMounted => Partition.IsMounted;
    public bool IsRemovable => Partition.IsRemovable;
    public string FormattedSize => FormatSize(Partition.Size);

    private bool _isActive;
    public bool IsActive
    {
        get => _isActive;
        set => this.RaiseAndSetIfChanged(ref _isActive, value);
    }

    public string MountStatusText => IsMounted ? $"Mounted at {MountPoint}" : "Not mounted";

    public IBrush MountDotColor => IsMounted
        ? Brush.Parse("#34D399")  // Green
        : Brush.Parse("#64748B"); // Gray

    public string DriveIcon => IsRemovable ? "💾" : "🖴";

    public EFIPartitionViewModel(EFIPartition partition)
    {
        Partition = partition;
    }

    private static string FormatSize(long bytes)
    {
        if (bytes < 1024) return $"{bytes} B";
        if (bytes < 1024 * 1024) return $"{bytes / 1024.0:F1} KB";
        if (bytes < 1024 * 1024 * 1024) return $"{bytes / (1024.0 * 1024.0):F1} MB";
        return $"{bytes / (1024.0 * 1024.0 * 1024.0):F2} GB";
    }
}

