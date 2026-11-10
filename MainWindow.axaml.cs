using System;
using Avalonia.Controls;
using Avalonia.Interactivity;
using SelfSecureBoot.Core;
using SelfSecureBoot.ViewModels;

namespace SelfSecureBoot;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
        var vm = new MainWindowViewModel(this);
        DataContext = vm;
    }

    protected override void OnDataContextChanged(EventArgs e)
    {
        base.OnDataContextChanged(e);
        if (DataContext is MainWindowViewModel vm)
            vm.SetWindow(this);
    }

    private void OnSelectPartitionClick(object? sender, RoutedEventArgs e)
    {
        if (sender is Button btn && btn.DataContext is EFIPartitionViewModel part && DataContext is MainWindowViewModel vm)
            _ = vm.SelectPartitionAsync(part);
    }

    private void OnMountPartitionClick(object? sender, RoutedEventArgs e)
    {
        if (sender is Button btn && btn.DataContext is EFIPartitionViewModel part && DataContext is MainWindowViewModel vm)
            _ = vm.MountPartitionAsync(part);
    }

    private void OnUnmountPartitionClick(object? sender, RoutedEventArgs e)
    {
        if (sender is Button btn && btn.DataContext is EFIPartitionViewModel part && DataContext is MainWindowViewModel vm)
            _ = vm.UnmountPartitionAsync(part);
    }

    private void OnApplyFixClick(object? sender, RoutedEventArgs e)
    {
        if (sender is Button btn && btn.DataContext is ConfigWarning warning && warning.Fix != null && DataContext is MainWindowViewModel vm)
            _ = vm.ApplyFixAsync(warning.Fix);
    }

    private void OnFilterTabClick(object? sender, RoutedEventArgs e)
    {
        if (sender is Button btn && btn.Tag is string tag && DataContext is MainWindowViewModel vm)
            vm.ActiveTabFilter = tag;
    }
}
