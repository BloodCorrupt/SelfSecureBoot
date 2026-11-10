using System;
using Avalonia;
using Avalonia.ReactiveUI;
using SelfSecureBoot.Core;
using SelfSecureBoot.Tests;

namespace SelfSecureBoot;

public class Program
{
    [STAThread]
    public static void Main(string[] args)
    {
        if (args.Length > 0 && args[0].Equals("--test", StringComparison.OrdinalIgnoreCase))
        {
            bool ok = SelfTestRunner.RunTests();
            Environment.Exit(ok ? 0 : 1);
            return;
        }

        if (CliHandler.IsCliCommand(args))
        {
            int code = CliHandler.Run(args);
            Environment.Exit(code);
            return;
        }

        AppPaths.EnsureDirectories();

        BuildAvaloniaApp().StartWithClassicDesktopLifetime(args);
    }

    public static AppBuilder BuildAvaloniaApp()
        => AppBuilder.Configure<App>()
            .UsePlatformDetect()
            .WithInterFont()
            .LogToTrace()
            .UseReactiveUI();
}

