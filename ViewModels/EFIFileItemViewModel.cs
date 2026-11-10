using System;
using Avalonia.Media;
using ReactiveUI;
using SelfSecureBoot.Core;

namespace SelfSecureBoot.ViewModels;

public sealed class EFIFileItemViewModel : ReactiveObject
{
    public EFIFileEntry Entry { get; }

    private bool _isSelected;
    public bool IsSelected
    {
        get => _isSelected;
        set => this.RaiseAndSetIfChanged(ref _isSelected, value);
    }

    public string Id => Entry.Id;
    public string FullPath => Entry.FullPath;
    public string RelativePath => Entry.RelativePath;
    public long Size => Entry.Size;
    public string FormattedSize => FormatSize(Entry.Size);
    public string Role => Entry.Role.DisplayName();
    public Verdict Verdict => Entry.Verdict;
    public string StatusText => Entry.Verdict.DisplayName();
    public string SignerDescription => Entry.SignerDescription;

    public EFIFileItemViewModel(EFIFileEntry entry)
    {
        Entry = entry;
    }

    public IBrush StatusForeground => Verdict switch
    {
        Verdict.NeedsSignature or Verdict.SignedInvalid => Brush.Parse("#F87171"), // Red
        Verdict.SignedByUs => Brush.Parse("#34D399"),                             // Emerald Green
        Verdict.SignedOther => Brush.Parse("#60A5FA"),                            // Blue
        _ => Brush.Parse("#94A3B8")                                               // Muted Slate
    };

    public IBrush StatusBadgeBackground => Verdict switch
    {
        Verdict.NeedsSignature or Verdict.SignedInvalid => Brush.Parse("#2A1215"),
        Verdict.SignedByUs => Brush.Parse("#10281F"),
        Verdict.SignedOther => Brush.Parse("#13233A"),
        _ => Brush.Parse("#1C1E2F")
    };

    public IBrush StatusBadgeBorder => Verdict switch
    {
        Verdict.NeedsSignature or Verdict.SignedInvalid => Brush.Parse("#7F1D1D"),
        Verdict.SignedByUs => Brush.Parse("#059669"),
        Verdict.SignedOther => Brush.Parse("#2563EB"),
        _ => Brush.Parse("#2A2D45")
    };

    public string StatusIcon => Verdict switch
    {
        Verdict.NeedsSignature => "⚠️",
        Verdict.SignedByUs => "🛡️",
        Verdict.SignedOther => "✔️",
        Verdict.SignedInvalid => "❌",
        Verdict.DisabledInConfig or Verdict.NotLoaded => "⏸️",
        Verdict.AppleSigned => "🍎",
        _ => "❓"
    };

    private static string FormatSize(long bytes)
    {
        if (bytes < 1024) return $"{bytes} B";
        if (bytes < 1024 * 1024) return $"{bytes / 1024.0:F1} KB";
        return $"{bytes / (1024.0 * 1024.0):F2} MB";
    }
}

