using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reactive.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Input;
using Avalonia.Controls;
using Avalonia.Media;
using Avalonia.Platform.Storage;
using Avalonia.Threading;
using ReactiveUI;
using SelfSecureBoot.Core;

namespace SelfSecureBoot.ViewModels;

public sealed class MainWindowViewModel : ReactiveObject
{
    private Window? _window;
    public KeyStore KeyStore { get; } = new();

    private readonly ConcurrentQueue<string> _logQueue = new();
    private readonly DispatcherTimer _logTimer;

    // --- State Properties ---
    private bool _isBusy;
    public bool IsBusy
    {
        get => _isBusy;
        set => this.RaiseAndSetIfChanged(ref _isBusy, value);
    }

    private string _busyText = "";
    public string BusyText
    {
        get => _busyText;
        set => this.RaiseAndSetIfChanged(ref _busyText, value);
    }

    private string _selectedPath = "";
    public string SelectedPath
    {
        get => _selectedPath;
        set => this.RaiseAndSetIfChanged(ref _selectedPath, value);
    }

    private EFIPartitionViewModel? _selectedPartition;
    public EFIPartitionViewModel? SelectedPartition
    {
        get => _selectedPartition;
        set => this.RaiseAndSetIfChanged(ref _selectedPartition, value);
    }

    private FirmwareState _firmware = FirmwareState.Read();
    public FirmwareState Firmware
    {
        get => _firmware;
        set => this.RaiseAndSetIfChanged(ref _firmware, value);
    }

    private CertificateInfo? _keyInfo;
    public CertificateInfo? KeyInfo
    {
        get => _keyInfo;
        set => this.RaiseAndSetIfChanged(ref _keyInfo, value);
    }

    private OpenCoreConfig? _config;
    public OpenCoreConfig? Config
    {
        get => _config;
        set
        {
            this.RaiseAndSetIfChanged(ref _config, value);
            UpdateConfigWarnings();
        }
    }

    public ObservableCollection<ConfigWarning> ConfigWarnings { get; } = new();
    public ObservableCollection<EFIPartitionViewModel> Partitions { get; } = new();
    public ObservableCollection<EFIFileItemViewModel> Files { get; } = new();

    public ObservableCollection<string> AvailableDriveLetters { get; } = new();

    private string _selectedMountLetter = "S:";
    public string SelectedMountLetter
    {
        get => _selectedMountLetter;
        set
        {
            this.RaiseAndSetIfChanged(ref _selectedMountLetter, value);
            this.RaisePropertyChanged(nameof(MountButtonLabel));
        }
    }

    public string MountButtonLabel => $"Mount ({SelectedMountLetter})";

    private string _searchFilter = "";
    public string SearchFilter
    {
        get => _searchFilter;
        set
        {
            this.RaiseAndSetIfChanged(ref _searchFilter, value);
            FilterFiles();
        }
    }

    private string _activeTabFilter = "All"; // All, NeedsSigning, SignedWithKey, Other
    public string ActiveTabFilter
    {
        get => _activeTabFilter;
        set
        {
            this.RaiseAndSetIfChanged(ref _activeTabFilter, value);
            FilterFiles();
        }
    }

    public ObservableCollection<EFIFileItemViewModel> FilteredFiles { get; } = new();

    private string _logContent = "";
    public string LogContent
    {
        get => _logContent;
        set => this.RaiseAndSetIfChanged(ref _logContent, value);
    }

    // --- Header & Badge Properties ---
    public bool IsElevated => DiskService.IsElevated;
    public string ElevationBadgeText => IsElevated ? "🛡️ Administrator" : "⚠️ Standard User";
    public IBrush ElevationBadgeForeground => IsElevated ? Brush.Parse("#34D399") : Brush.Parse("#F59E0B");
    public IBrush ElevationBadgeBackground => IsElevated ? Brush.Parse("#10281F") : Brush.Parse("#2C1D11");
    public IBrush ElevationBadgeBorder => IsElevated ? Brush.Parse("#059669") : Brush.Parse("#D97706");
    public string ElevationTooltip => IsElevated
        ? "Running with elevated administrator privileges"
        : "Running as standard user. Click to relaunch as Administrator to mount protected EFI partitions.";

    public string SecureBootBadgeText => Firmware.SecureBootEnabled switch
    {
        true => Firmware.SetupMode == true ? "Secure Boot: Setup Mode" : "Secure Boot: Enforced",
        false => "Secure Boot: Off",
        null => "Secure Boot: Unknown"
    };

    public IBrush SecureBootBadgeForeground => Firmware.SecureBootEnabled == true
        ? Brush.Parse("#34D399")
        : (Firmware.SecureBootEnabled == false ? Brush.Parse("#F59E0B") : Brush.Parse("#94A3B8"));

    public IBrush SecureBootBadgeBackground => Firmware.SecureBootEnabled == true
        ? Brush.Parse("#10281F")
        : (Firmware.SecureBootEnabled == false ? Brush.Parse("#2C1D11") : Brush.Parse("#1C1E2F"));

    public IBrush SecureBootBadgeBorder => Firmware.SecureBootEnabled == true
        ? Brush.Parse("#059669")
        : (Firmware.SecureBootEnabled == false ? Brush.Parse("#D97706") : Brush.Parse("#2A2D45"));

    public bool HasKey => KeyStore.Exists;
    public string KeyBadgeText => HasKey ? $"🔑 {KeyInfo?.Subject ?? "Key Ready"}" : "🔑 No Key";
    public IBrush KeyBadgeForeground => HasKey ? Brush.Parse("#C4B5FD") : Brush.Parse("#F59E0B");
    public IBrush KeyBadgeBackground => HasKey ? Brush.Parse("#2E1A47") : Brush.Parse("#2C1D11");
    public IBrush KeyBadgeBorder => HasKey ? Brush.Parse("#7C3AED") : Brush.Parse("#D97706");

    // --- Summary & Next Step Guidance ---
    public int TotalFileCount => Files.Count;
    public int NeedsSigningCount => Files.Count(f => f.Verdict.BlocksSecureBoot());
    public int SignedByUsCount => Files.Count(f => f.Verdict == Verdict.SignedByUs);
    public int SelectedCount => Files.Count(f => f.IsSelected);

    public bool HasNoPartitions => Partitions.Count == 0;
    public bool HasConfigWarnings => ConfigWarnings.Count > 0;

    public bool ReadyForSecureBoot =>
        Files.Count > 0 && NeedsSigningCount == 0 && ConfigWarnings.Count == 0;

    public IBrush ReadyBadgeBackground => ReadyForSecureBoot ? Brush.Parse("#10281F") : Brush.Parse("#2A1215");
    public IBrush ReadyBadgeBorder => ReadyForSecureBoot ? Brush.Parse("#059669") : Brush.Parse("#7F1D1D");
    public IBrush ReadyBadgeForeground => ReadyForSecureBoot ? Brush.Parse("#34D399") : Brush.Parse("#F87171");
    public string ReadyBadgeIcon => ReadyForSecureBoot ? "🛡️" : "⚠️";
    public string ReadyBadgeText => ReadyForSecureBoot ? "Ready for Secure Boot" : "Would be rejected under Secure Boot";

    public IBrush NeedsSigningForeground => NeedsSigningCount > 0 ? Brush.Parse("#F87171") : Brush.Parse("#34D399");

    public string NextStepMessage
    {
        get
        {
            if (string.IsNullOrWhiteSpace(SelectedPath))
                return "Select an EFI partition in the sidebar or browse to an EFI directory to scan.";

            if (IsBusy)
                return BusyText;

            if (!HasKey)
                return "Generate or import a signing key in the Signing Key panel below.";

            if (Files.Count == 0)
                return "No .efi files detected in the selected directory. Ensure the path contains EFI bootloaders or drivers.";

            if (ConfigWarnings.Count > 0)
                return "Fix the OpenCore config.plist warning(s) above with their inline Fix buttons.";

            if (NeedsSigningCount > 0)
                return $"Press 'Sign needed' to sign {NeedsSigningCount} file(s) the firmware would reject under Secure Boot.";

            if (SelectedPartition?.IsRemovable == true)
                return "All files signed! Eject the USB stick, boot your PC, and enroll db.cer in the BIOS.";

            if (Firmware.SecureBootEnabled == true)
                return "All signed and UEFI Secure Boot is enforced. Nothing to do until your next OpenCore update!";

            return "All signed! Use Key panel → 'Export for BIOS' onto a FAT32 USB stick, append db.cer in BIOS db, enable Secure Boot and reboot.";
        }
    }

    // --- Commands ---
    public ICommand BrowseFolderCommand { get; }
    public ICommand ScanPathCommand { get; }
    public ICommand RefreshPartitionsCommand { get; }
    public ICommand RelaunchElevatedCommand { get; }
    public ICommand QuickFolderCommand { get; }

    public ICommand SignNeededCommand { get; }
    public ICommand SignSelectedCommand { get; }
    public ICommand ReSignAllCommand { get; }
    public ICommand RevertSelectedCommand { get; }
    public ICommand RevertAllCommand { get; }
    public ICommand RestoreConfigCommand { get; }

    public ICommand GenerateKeyDialogCommand { get; }
    public ICommand ImportKeyCommand { get; }
    public ICommand ExportBiosCommand { get; }
    public ICommand OpenKeyFolderCommand { get; }
    public ICommand OpenBackupsFolderCommand { get; }
    public ICommand OpenGuideCommand { get; }
    public ICommand ClearLogsCommand { get; }

    public MainWindowViewModel(Window? window = null)
    {
        _window = window;

        // Log Timer for batch UI updates
        _logTimer = new DispatcherTimer
        {
            Interval = TimeSpan.FromMilliseconds(100)
        };
        _logTimer.Tick += ProcessLogQueue;
        _logTimer.Start();

        // Initialize Commands
        BrowseFolderCommand = ReactiveCommand.CreateFromTask(BrowseFolderAsync);
        ScanPathCommand = ReactiveCommand.CreateFromTask(ScanCurrentPathAsync);
        RefreshPartitionsCommand = ReactiveCommand.CreateFromTask(RefreshPartitionsAsync);
        RelaunchElevatedCommand = ReactiveCommand.Create(RelaunchElevated);
        QuickFolderCommand = ReactiveCommand.Create<string>(NavigateQuickFolder);

        SignNeededCommand = ReactiveCommand.CreateFromTask(SignNeededAsync);
        SignSelectedCommand = ReactiveCommand.CreateFromTask(SignSelectedAsync);
        ReSignAllCommand = ReactiveCommand.CreateFromTask(ReSignAllAsync);
        RevertSelectedCommand = ReactiveCommand.CreateFromTask(RevertSelectedAsync);
        RevertAllCommand = ReactiveCommand.CreateFromTask(RevertAllAsync);
        RestoreConfigCommand = ReactiveCommand.CreateFromTask(RestoreConfigAsync);

        GenerateKeyDialogCommand = ReactiveCommand.CreateFromTask(OpenGenerateKeyDialogAsync);
        ImportKeyCommand = ReactiveCommand.CreateFromTask(ImportKeyAsync);
        ExportBiosCommand = ReactiveCommand.CreateFromTask(ExportBiosAsync);
        OpenKeyFolderCommand = ReactiveCommand.Create(OpenKeyFolder);
        OpenBackupsFolderCommand = ReactiveCommand.Create(OpenBackupsFolder);
        OpenGuideCommand = ReactiveCommand.Create(OpenGuideWindow);
        ClearLogsCommand = ReactiveCommand.Create(() => LogContent = "");

        RefreshKeyInfo();
        AppendLog("EFI Signer initialized. Cross-platform UEFI Secure Boot manager.");
        if (IsElevated) AppendLog("Running with Administrator privileges.");
        else AppendLog("Running as standard user. (Mounting EFI partitions may require elevation).");

        _ = RefreshPartitionsAsync();
    }

    public void SetWindow(Window window)
    {
        _window = window;
    }

    public void RefreshKeyInfo()
    {
        KeyInfo = KeyStore.GetCertificateInfo();
        this.RaisePropertyChanged(nameof(HasKey));
        this.RaisePropertyChanged(nameof(KeyBadgeText));
        this.RaisePropertyChanged(nameof(KeyBadgeForeground));
        this.RaisePropertyChanged(nameof(KeyBadgeBackground));
        this.RaisePropertyChanged(nameof(KeyBadgeBorder));
        this.RaisePropertyChanged(nameof(NextStepMessage));
    }

    public void AppendLog(string message)
    {
        string time = DateTime.Now.ToString("HH:mm:ss");
        _logQueue.Enqueue($"[{time}] {message}");
    }

    private void ProcessLogQueue(object? sender, EventArgs e)
    {
        if (_logQueue.IsEmpty) return;

        var sb = new StringBuilder(LogContent);
        while (_logQueue.TryDequeue(out var line))
        {
            sb.AppendLine(line);
        }

        // Limit log size to 1000 lines
        string text = sb.ToString();
        var lines = text.Split('\n');
        if (lines.Length > 1000)
        {
            text = string.Join('\n', lines.Skip(lines.Length - 1000));
        }

        LogContent = text;
    }

    public void RefreshAvailableDriveLetters()
    {
        var letters = DiskService.GetAvailableDriveLetters();
        AvailableDriveLetters.Clear();
        foreach (char c in letters)
        {
            AvailableDriveLetters.Add($"{c}:");
        }

        if (!AvailableDriveLetters.Contains(SelectedMountLetter) && AvailableDriveLetters.Count > 0)
        {
            SelectedMountLetter = AvailableDriveLetters[0];
        }
    }

    public async Task RefreshPartitionsAsync()
    {
        IsBusy = true;
        BusyText = "Scanning physical disks and EFI partitions...";
        try
        {
            RefreshAvailableDriveLetters();

            var parts = await Task.Run(() => DiskService.ListEFIPartitions());
            Partitions.Clear();

            EFIPartitionViewModel? defaultSelection = null;
            foreach (var p in parts)
            {
                var vm = new EFIPartitionViewModel(p);
                Partitions.Add(vm);
                if (defaultSelection == null && p.IsMounted)
                {
                    defaultSelection = vm;
                }
            }

            AppendLog($"Discovered {Partitions.Count} EFI partition(s) / volume(s). Available mount letters: {string.Join(", ", AvailableDriveLetters.Take(5))}...");
            this.RaisePropertyChanged(nameof(HasNoPartitions));

            if (SelectedPartition == null && defaultSelection != null)
            {
                await SelectPartitionAsync(defaultSelection);
            }
        }
        catch (Exception ex)
        {
            AppendLog($"Error discovering partitions: {ex.Message}");
        }
        finally
        {
            IsBusy = false;
            BusyText = "";
        }
    }

    public async Task SelectPartitionAsync(EFIPartitionViewModel part)
    {
        foreach (var p in Partitions) p.IsActive = (p == part);
        SelectedPartition = part;

        if (part.IsMounted && !string.IsNullOrEmpty(part.MountPoint))
        {
            SelectedPath = part.MountPoint;
            await ScanCurrentPathAsync();
        }
        else
        {
            SelectedPath = "";
            Files.Clear();
            FilteredFiles.Clear();
            Config = null;
            UpdateSummaryProperties();
            AppendLog($"Selected unmounted partition: {part.Id}. Click 'Mount' to mount and scan.");
        }
    }

    public async Task MountPartitionAsync(EFIPartitionViewModel part)
    {
        if (!IsElevated)
        {
            AppendLog("Mounting an EFI partition requires Administrator privileges.");
            RelaunchElevated();
            return;
        }

        char chosenChar = !string.IsNullOrEmpty(SelectedMountLetter) ? SelectedMountLetter[0] : 'S';

        IsBusy = true;
        BusyText = $"Mounting {part.Id} to {chosenChar}:...";
        try
        {
            string mountPoint = await Task.Run(() => DiskService.Mount(part.Partition, chosenChar));
            AppendLog($"Mounted {part.Id} successfully at {mountPoint}");
            await RefreshPartitionsAsync();

            var updated = Partitions.FirstOrDefault(p => p.Id == part.Id);
            if (updated != null)
            {
                await SelectPartitionAsync(updated);
            }
        }
        catch (Exception ex)
        {
            AppendLog($"Failed to mount {part.Id}: {ex.Message}");
        }
        finally
        {
            IsBusy = false;
            BusyText = "";
        }
    }

    public async Task UnmountPartitionAsync(EFIPartitionViewModel part)
    {
        IsBusy = true;
        BusyText = $"Unmounting {part.Id}...";
        try
        {
            await Task.Run(() => DiskService.Unmount(part.Partition));
            AppendLog($"Unmounted {part.Id}");
            await RefreshPartitionsAsync();
        }
        catch (Exception ex)
        {
            AppendLog($"Failed to unmount {part.Id}: {ex.Message}");
        }
        finally
        {
            IsBusy = false;
            BusyText = "";
        }
    }

    public async Task BrowseFolderAsync()
    {
        if (_window?.StorageProvider == null) return;

        var options = new FolderPickerOpenOptions
        {
            Title = "Select EFI Root or Partition Folder",
            AllowMultiple = false
        };

        var folders = await _window.StorageProvider.OpenFolderPickerAsync(options);
        if (folders.Count > 0)
        {
            string localPath = folders[0].Path.LocalPath;
            SelectedPath = localPath;
            await ScanCurrentPathAsync();
        }
    }

    public async Task ScanCurrentPathAsync()
    {
        if (string.IsNullOrWhiteSpace(SelectedPath) || !Directory.Exists(SelectedPath))
        {
            Files.Clear();
            FilteredFiles.Clear();
            Config = null;
            UpdateSummaryProperties();
            return;
        }

        IsBusy = true;
        BusyText = $"Scanning {SelectedPath}...";
        try
        {
            byte[]? trustedDer = KeyStore.CertificateDER;
            string path = SelectedPath;

            var (entries, config) = await Task.Run(() => Scanner.Scan(path, trustedDer));

            Files.Clear();
            foreach (var e in entries)
            {
                Files.Add(new EFIFileItemViewModel(e));
            }

            Config = config;
            FilterFiles();
            UpdateSummaryProperties();

            AppendLog($"Scanned {SelectedPath}: {entries.Count} EFI files found ({NeedsSigningCount} need signing).");
        }
        catch (Exception ex)
        {
            AppendLog($"Scan failed: {ex.Message}");
        }
        finally
        {
            IsBusy = false;
            BusyText = "";
        }
    }

    private void NavigateQuickFolder(string folderName)
    {
        if (string.IsNullOrWhiteSpace(SelectedPath)) return;
        string target = Path.Combine(SelectedPath, folderName);
        if (Directory.Exists(target))
        {
            SelectedPath = target;
            _ = ScanCurrentPathAsync();
        }
    }

    private void FilterFiles()
    {
        var items = Files.AsEnumerable();

        if (!string.IsNullOrWhiteSpace(SearchFilter))
        {
            items = items.Where(f => f.RelativePath.Contains(SearchFilter, StringComparison.OrdinalIgnoreCase) ||
                                     f.Role.Contains(SearchFilter, StringComparison.OrdinalIgnoreCase) ||
                                     f.SignerDescription.Contains(SearchFilter, StringComparison.OrdinalIgnoreCase));
        }

        items = ActiveTabFilter switch
        {
            "NeedsSigning" => items.Where(f => f.Verdict.BlocksSecureBoot()),
            "SignedWithKey" => items.Where(f => f.Verdict == Verdict.SignedByUs),
            "Other" => items.Where(f => !f.Verdict.BlocksSecureBoot() && f.Verdict != Verdict.SignedByUs),
            _ => items
        };

        FilteredFiles.Clear();
        foreach (var item in items)
        {
            FilteredFiles.Add(item);
        }
    }

    private void UpdateConfigWarnings()
    {
        ConfigWarnings.Clear();
        if (Config != null)
        {
            foreach (var w in Config.Warnings)
            {
                ConfigWarnings.Add(w);
            }
        }
        this.RaisePropertyChanged(nameof(HasConfigWarnings));
        this.RaisePropertyChanged(nameof(ReadyForSecureBoot));
        this.RaisePropertyChanged(nameof(ReadyBadgeBackground));
        this.RaisePropertyChanged(nameof(ReadyBadgeBorder));
        this.RaisePropertyChanged(nameof(ReadyBadgeForeground));
        this.RaisePropertyChanged(nameof(ReadyBadgeIcon));
        this.RaisePropertyChanged(nameof(ReadyBadgeText));
        this.RaisePropertyChanged(nameof(NextStepMessage));
    }

    private void UpdateSummaryProperties()
    {
        this.RaisePropertyChanged(nameof(TotalFileCount));
        this.RaisePropertyChanged(nameof(NeedsSigningCount));
        this.RaisePropertyChanged(nameof(SignedByUsCount));
        this.RaisePropertyChanged(nameof(SelectedCount));
        this.RaisePropertyChanged(nameof(ReadyForSecureBoot));
        this.RaisePropertyChanged(nameof(ReadyBadgeBackground));
        this.RaisePropertyChanged(nameof(ReadyBadgeBorder));
        this.RaisePropertyChanged(nameof(ReadyBadgeForeground));
        this.RaisePropertyChanged(nameof(ReadyBadgeIcon));
        this.RaisePropertyChanged(nameof(ReadyBadgeText));
        this.RaisePropertyChanged(nameof(NeedsSigningForeground));
        this.RaisePropertyChanged(nameof(NextStepMessage));
    }

    public async Task ApplyFixAsync(ConfigFix fix)
    {
        if (string.IsNullOrWhiteSpace(SelectedPath)) return;

        IsBusy = true;
        BusyText = $"Applying fix: {fix.Title}...";
        try
        {
            string backupDir = SelectedPartition != null
                ? KeyStore.GetOrCreateBackupFolder(SelectedPartition.Id, SelectedPartition.Partition.PartitionUUID, SelectedPartition.VolumeName)
                : KeyStore.BackupsDir;

            await Task.Run(() => OpenCoreConfig.ApplyFix(fix, SelectedPath, backupDir));
            AppendLog($"Applied config fix: {fix.Title}. Backup saved in {backupDir}");
            await ScanCurrentPathAsync();
        }
        catch (Exception ex)
        {
            AppendLog($"Failed to apply config fix: {ex.Message}");
        }
        finally
        {
            IsBusy = false;
            BusyText = "";
        }
    }

    public async Task SignNeededAsync()
    {
        var needed = Files.Where(f => f.Verdict.BlocksSecureBoot()).Select(f => f.Entry).ToList();
        if (needed.Count == 0) return;
        await SignEntriesAsync(needed);
    }

    public async Task SignSelectedAsync()
    {
        var selected = Files.Where(f => f.IsSelected).Select(f => f.Entry).ToList();
        if (selected.Count == 0) return;
        await SignEntriesAsync(selected);
    }

    public async Task ReSignAllAsync()
    {
        var all = Files.Where(f => f.Entry.Status is not FileStatus.NotPEStatus &&
                                   f.Entry.Role != FileRole.AppleUpdater &&
                                   f.Entry.Role != FileRole.AppleBoot &&
                                   f.Entry.Verdict != Verdict.DisabledInConfig &&
                                   f.Entry.Verdict != Verdict.AppleSigned)
                       .Select(f => f.Entry).ToList();
        if (all.Count == 0) return;
        await SignEntriesAsync(all);
    }

    private async Task SignEntriesAsync(List<EFIFileEntry> entries)
    {
        if (!KeyStore.Exists)
        {
            AppendLog("No signing key found. Generate or import a signing key first.");
            return;
        }

        IsBusy = true;
        BusyText = $"Signing {entries.Count} file(s)...";
        try
        {
            using var identity = KeyStore.Identity();
            string backupDir = SelectedPartition != null
                ? KeyStore.GetOrCreateBackupFolder(SelectedPartition.Id, SelectedPartition.Partition.PartitionUUID, SelectedPartition.VolumeName)
                : Path.Combine(KeyStore.BackupsDir, $"{DateTime.Now:yyyy-MM-dd} Manual");

            int signedCount = 0;
            int failedCount = 0;

            await Task.Run(() =>
            {
                foreach (var entry in entries)
                {
                    var outcome = SignerService.Sign(entry, identity, backupDir);
                    if (outcome.Error == null)
                    {
                        signedCount++;
                        AppendLog($"Signed: {entry.RelativePath}");
                    }
                    else
                    {
                        failedCount++;
                        AppendLog($"FAILED signing {entry.RelativePath}: {outcome.Error}");
                    }
                }
            });

            AppendLog($"Signed {signedCount} file(s) successfully. Backups preserved in {backupDir}");
            if (failedCount > 0)
            {
                AppendLog($"WARNING: {failedCount} file(s) failed signing.");
            }

            await ScanCurrentPathAsync();
        }
        catch (Exception ex)
        {
            AppendLog($"Signing operation failed: {ex.Message}");
        }
        finally
        {
            IsBusy = false;
            BusyText = "";
        }
    }

    public async Task RevertSelectedAsync()
    {
        var selected = Files.Where(f => f.IsSelected).Select(f => f.Entry).ToList();
        if (selected.Count == 0) return;
        await RevertEntriesAsync(selected);
    }

    public async Task RevertAllAsync()
    {
        var revertable = Files.Where(f => f.Verdict is Verdict.SignedByUs or Verdict.SignedInvalid or Verdict.SignedOther)
                              .Select(f => f.Entry).ToList();
        if (revertable.Count == 0) return;
        await RevertEntriesAsync(revertable);
    }

    private async Task RevertEntriesAsync(List<EFIFileEntry> entries)
    {
        IsBusy = true;
        BusyText = $"Reverting {entries.Count} file(s)...";
        try
        {
            var backupFolders = SelectedPartition != null
                ? KeyStore.GetBackupFolders(SelectedPartition.Id, SelectedPartition.Partition.PartitionUUID)
                : Directory.GetDirectories(KeyStore.BackupsDir).ToList();

            int revertedCount = 0;
            int failedCount = 0;

            await Task.Run(() =>
            {
                foreach (var entry in entries)
                {
                    var outcome = RestoreService.Revert(entry, backupFolders);
                    if (outcome.Error == null)
                    {
                        revertedCount++;
                        AppendLog($"Reverted {entry.RelativePath}: {outcome.Method}");
                    }
                    else
                    {
                        failedCount++;
                        AppendLog($"FAILED reverting {entry.RelativePath}: {outcome.Error}");
                    }
                }
            });

            AppendLog($"Revert completed: {revertedCount} restored, {failedCount} errors.");
            await ScanCurrentPathAsync();
        }
        catch (Exception ex)
        {
            AppendLog($"Revert operation failed: {ex.Message}");
        }
        finally
        {
            IsBusy = false;
            BusyText = "";
        }
    }

    public async Task RestoreConfigAsync()
    {
        if (string.IsNullOrWhiteSpace(SelectedPath)) return;

        IsBusy = true;
        BusyText = "Restoring original config.plist...";
        try
        {
            var backupFolders = SelectedPartition != null
                ? KeyStore.GetBackupFolders(SelectedPartition.Id, SelectedPartition.Partition.PartitionUUID)
                : Directory.GetDirectories(KeyStore.BackupsDir).ToList();

            string restoredName = await Task.Run(() => RestoreService.RestoreConfig(SelectedPath, backupFolders));
            AppendLog($"config.plist successfully restored from backup {restoredName}");
            await ScanCurrentPathAsync();
        }
        catch (Exception ex)
        {
            AppendLog($"Failed to restore config.plist: {ex.Message}");
        }
        finally
        {
            IsBusy = false;
            BusyText = "";
        }
    }

    public async Task OpenGenerateKeyDialogAsync()
    {
        if (_window == null) return;
        var dialog = new GenerateKeyWindow();
        var result = await dialog.ShowDialog<bool>(_window);
        if (result)
        {
            RefreshKeyInfo();
            AppendLog($"Generated new RSA signing key in {KeyStore.DirectoryPath}");
            await ScanCurrentPathAsync();
        }
    }

    public async Task ImportKeyAsync()
    {
        if (_window?.StorageProvider == null) return;

        var keyFiles = await _window.StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
        {
            Title = "Choose RSA Private Key (PEM, e.g. db.key)",
            AllowMultiple = false
        });
        if (keyFiles.Count == 0) return;

        var certFiles = await _window.StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
        {
            Title = "Choose Certificate (PEM or DER, e.g. db.crt or db.cer)",
            AllowMultiple = false
        });
        if (certFiles.Count == 0) return;

        try
        {
            string keyPath = keyFiles[0].Path.LocalPath;
            string certPath = certFiles[0].Path.LocalPath;

            KeyStore.ImportKey(keyPath, certPath);
            RefreshKeyInfo();
            AppendLog($"Imported private key ({Path.GetFileName(keyPath)}) and certificate ({Path.GetFileName(certPath)})");
            await ScanCurrentPathAsync();
        }
        catch (Exception ex)
        {
            AppendLog($"Failed to import key: {ex.Message}");
        }
    }

    public async Task ExportBiosAsync()
    {
        if (_window?.StorageProvider == null) return;

        if (!KeyStore.Exists)
        {
            AppendLog("Cannot export: No signing key exists yet. Generate a key first.");
            return;
        }

        var folders = await _window.StorageProvider.OpenFolderPickerAsync(new FolderPickerOpenOptions
        {
            Title = "Choose Target Folder for db.cer and db.esl (e.g. FAT32 USB Stick)",
            AllowMultiple = false
        });

        if (folders.Count > 0)
        {
            try
            {
                string target = folders[0].Path.LocalPath;
                var exported = KeyStore.ExportCertificate(target);
                AppendLog($"Exported {string.Join(", ", exported.Select(Path.GetFileName))} to {target}");
            }
            catch (Exception ex)
            {
                AppendLog($"Failed to export certificate files: {ex.Message}");
            }
        }
    }

    public void OpenKeyFolder()
    {
        try
        {
            OpenInExplorer(KeyStore.DirectoryPath);
        }
        catch (Exception ex)
        {
            AppendLog($"Could not open key folder: {ex.Message}");
        }
    }

    public void OpenBackupsFolder()
    {
        try
        {
            OpenInExplorer(KeyStore.BackupsDir);
        }
        catch (Exception ex)
        {
            AppendLog($"Could not open backups folder: {ex.Message}");
        }
    }

    public void OpenGuideWindow()
    {
        var guide = new GuideWindow();
        guide.Show();
    }

    public void RelaunchElevated()
    {
        AppendLog("Requesting Administrator elevation...");
        DiskService.RelaunchAsElevated();
    }

    private static void OpenInExplorer(string path)
    {
        if (OperatingSystem.IsWindows())
        {
            Process.Start("explorer.exe", path);
        }
        else if (OperatingSystem.IsMacOS())
        {
            Process.Start("open", path);
        }
        else
        {
            Process.Start("xdg-open", path);
        }
    }
}
