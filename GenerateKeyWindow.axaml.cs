using System;
using Avalonia.Controls;
using Avalonia.Interactivity;
using SelfSecureBoot.Core;

namespace SelfSecureBoot;

public partial class GenerateKeyWindow : Window
{
    public GenerateKeyWindow()
    {
        InitializeComponent();
    }

    private void OnCancelClick(object? sender, RoutedEventArgs e)
    {
        Close(false);
    }

    private void OnGenerateClick(object? sender, RoutedEventArgs e)
    {
        string cn = TxtCommonName.Text?.Trim() ?? "";
        if (string.IsNullOrEmpty(cn)) cn = "OpenCore Secure Boot Signing";

        int years = (int)Math.Round(SliderYears.Value);
        if (years < 1) years = 1;

        int keySize = CmbKeySize.SelectedIndex switch
        {
            1 => 3072,
            2 => 4096,
            _ => 2048
        };

        try
        {
            var keyStore = new KeyStore();
            keyStore.Generate(cn, years * 365, keySize);
            Close(true);
        }
        catch
        {
            Close(false);
        }
    }
}
