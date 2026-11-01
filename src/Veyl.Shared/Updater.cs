using System.Diagnostics;
using System.Net.Http;
using System.Security.Cryptography;

namespace Veyl.Shared;

public sealed class UpdateFailed(string message) : Exception(message);

/// <summary>
/// Downloads the newer VEYL-Setup.exe named by the release manifest at the installed
/// manifest's UpdateUrl, checks its SHA-256 against that manifest and starts it.
/// The setup closes VEYL itself and offers "Update".
/// </summary>
public static class Updater
{
    private static readonly HttpClient Http = Web.Client(TimeSpan.FromSeconds(15));

    public static string DownloadDir => Path.Combine(Path.GetTempPath(), "VEYL-Update");

    public static async Task<Manifest> FetchRemoteAsync(string? url, CancellationToken token = default)
    {
        if (string.IsNullOrEmpty(url)) throw new UpdateFailed("This build has no update address.");
        try
        {
            return Manifest.Parse(await Http.GetStringAsync(url, token))
                ?? throw new UpdateFailed("The release manifest is empty.");
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or System.Text.Json.JsonException)
        {
            throw new UpdateFailed($"Couldn't read the release manifest: {ex.Message}");
        }
    }

    /// <summary>Downloads and verifies the setup. Returns its path. Progress is 0..1.</summary>
    public static async Task<string> DownloadAsync(Manifest remote, string currentVersion, IProgress<double> progress, CancellationToken token = default)
    {
        if (!Manifest.IsNewer(remote.Version, currentVersion))
            throw new UpdateFailed($"The release on the server ({remote.Version}) isn't newer than this one.");
        // Plain http only for a local test server; anything real must be https.
        if (!Uri.TryCreate(remote.DownloadUrl, UriKind.Absolute, out var uri) || (uri.Scheme != Uri.UriSchemeHttps && !uri.IsLoopback))
            throw new UpdateFailed("The release manifest has no https download address.");
        if (remote.SetupSha256.Length != 64)
            throw new UpdateFailed("The release manifest has no SHA-256 for the installer, so it can't be checked.");

        Directory.CreateDirectory(DownloadDir);
        string path = Path.Combine(DownloadDir, $"VEYL-Setup-{remote.Version}.exe");
        string partial = path + ".part";

        try
        {
            using var response = await Http.GetAsync(uri, HttpCompletionOption.ResponseHeadersRead, token);
            response.EnsureSuccessStatusCode();
            long total = response.Content.Headers.ContentLength ?? remote.SetupSize;

            using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            await using (var input = await response.Content.ReadAsStreamAsync(token))
            await using (var output = File.Create(partial))
            {
                var buffer = new byte[1 << 16];
                long done = 0;
                int n;
                while ((n = await input.ReadAsync(buffer, token)) > 0)
                {
                    await output.WriteAsync(buffer.AsMemory(0, n), token);
                    sha.AppendData(buffer, 0, n);
                    done += n;
                    if (total > 0) progress.Report(Math.Min(1.0, (double)done / total));
                }
            }

            string actual = Convert.ToHexString(sha.GetHashAndReset());
            if (!actual.Equals(remote.SetupSha256, StringComparison.OrdinalIgnoreCase))
                throw new UpdateFailed("The downloaded installer doesn't match the release's SHA-256. It was deleted.");

            File.Move(partial, path, overwrite: true);
            return path;
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or IOException)
        {
            throw new UpdateFailed($"Download failed: {ex.Message}");
        }
        finally
        {
            try { File.Delete(partial); } catch (IOException) { }
        }
    }

    /// <summary>
    /// Starts the setup through Explorer rather than as our child: the setup kills VEYL's
    /// whole process tree before replacing files, and it would be in that tree otherwise.
    /// </summary>
    public static void StartSetup(string path) =>
        Process.Start(new ProcessStartInfo("explorer.exe", $"\"{path}\"") { UseShellExecute = false })?.Dispose();
}
