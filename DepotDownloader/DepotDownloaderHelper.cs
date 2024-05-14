using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using SteamKit2;

namespace DepotDownloader;

/// <summary>
/// DepotDownloader class
/// </summary>
public static class DepotDownloaderHelper
{
    private static readonly char[] newLineCharacters = ['\n', '\r'];

    /// <summary>
    /// Downloads steam depot based on app id and depot id, can also specify manifest id for other veer
    /// </summary>
    /// <param name="appId"></param>
    /// <param name="depotManifests"></param>
    /// <param name="dir"></param>
    /// <param name="validate"></param>
    /// <param name="branch"></param>
    public static async Task DownloadDepotAsync(uint appId, List<(uint, ulong)> depotManifests, string dir, bool validate, 
        string branch = ContentDownloader.DEFAULT_BRANCH)
    {
        DebugLog.Enabled = false;
        
        if (AccountSettingsStore.Instance == null)
        {
            AccountSettingsStore.LoadFromFile("account.config");
        }
        
        ContentDownloader.Config.InstallDirectory = dir;
        ContentDownloader.Config.VerifyAll = validate;
        ContentDownloader.Config.MaxServers = 20;
        ContentDownloader.Config.MaxDownloads = 8;
        ContentDownloader.Config.MaxServers = Math.Max(ContentDownloader.Config.MaxServers, ContentDownloader.Config.MaxDownloads);

        List<(uint depotId, ulong manifestId)> depotManifestIds = depotManifests;
        if (InitializeSteam(null, null))
        {
            try
            {
                await ContentDownloader.DownloadAppAsync(appId, depotManifestIds, branch, null, null, "english", 
                        false, false).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is ContentDownloaderException || ex is OperationCanceledException)
            {
                Console.WriteLine(ex.Message);
            }
            catch (Exception e)
            {
                Console.WriteLine("Download failed to due to an unhandled exception: {0}", e.Message);
                throw;
            }
            finally
            {
                ContentDownloader.ShutdownSteam3();
            }
        }
        else
        {
            Console.WriteLine("Error: InitializeSteam failed");
        }
        
    }

    static bool InitializeSteam(string username, string password)
    {
        if (username != null && password == null &&
            (!ContentDownloader.Config.RememberPassword || !AccountSettingsStore.Instance.LoginTokens.ContainsKey(username)))
        {
            do
            {
                Console.Write("Enter account password for \"{0}\": ", username);
                if (Console.IsInputRedirected)
                {
                    password = Console.ReadLine();
                }
                else
                {
                    // Avoid console echoing of password
                    password = Util.ReadPassword();
                }

                Console.WriteLine();
            } while (string.Empty == password);
        }
        else if (username == null)
        {
            Console.WriteLine("No username given. Using anonymous account with dedicated server subscription.");
        }

        return ContentDownloader.InitializeSteam3(username, password);
    }
}