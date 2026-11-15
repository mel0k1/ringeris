using System.Diagnostics;
using System.Text;

namespace Ringeris.App.Services;

public static class ProcessRunner
{
    public static async Task RunAsync(string exe, string args, Action<string> onLine, CancellationToken token)
    {
        using var process = Build(exe, args);
        using var registration = token.Register(() =>
        {
            try
            {
                process.Kill(true);
            }
            catch
            {
            }
        });
        process.Start();
        var reader = Task.Run(async () =>
        {
            while (await process.StandardOutput.ReadLineAsync() is { } line)
            {
                onLine(line);
            }
        });
        await Task.Run(() => process.WaitForExit());
        try
        {
            await reader;
        }
        catch
        {
        }
        token.ThrowIfCancellationRequested();
    }

    public static async Task<List<string>> CollectAsync(string exe, string args, CancellationToken token)
    {
        var lines = new List<string>();
        using var process = Build(exe, args);
        using var registration = token.Register(() =>
        {
            try
            {
                process.Kill(true);
            }
            catch
            {
            }
        });
        process.Start();
        var reader = Task.Run(async () =>
        {
            while (await process.StandardOutput.ReadLineAsync() is { } line)
            {
                lock (lines)
                {
                    lines.Add(line);
                }
            }
        });
        await Task.Run(() => process.WaitForExit());
        try
        {
            await reader;
        }
        catch
        {
        }
        token.ThrowIfCancellationRequested();
        lock (lines)
        {
            return lines;
        }
    }

    private static Process Build(string exe, string args)
    {
        return new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = exe,
                Arguments = args,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                StandardOutputEncoding = Encoding.UTF8,
            },
            EnableRaisingEvents = false,
        };
    }
}
