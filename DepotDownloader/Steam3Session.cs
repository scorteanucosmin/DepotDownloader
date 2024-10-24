// This file is subject to the terms and conditions defined
// in file 'LICENSE', which is part of this source code package.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using QRCoder;
using SteamKit2;
using SteamKit2.Authentication;
using SteamKit2.CDN;
using SteamKit2.Internal;

namespace DepotDownloader;

class Steam3Session
{
    public bool IsLoggedOn { get; private set; }

    public ReadOnlyCollection<SteamApps.LicenseListCallback.License> Licenses
    {
        get;
        private set;
    }

    public Dictionary<uint, ulong> AppTokens { get; } = [];
    public Dictionary<uint, ulong> PackageTokens { get; } = [];
    public Dictionary<uint, byte[]> DepotKeys { get; } = [];
    public ConcurrentDictionary<(uint, string), TaskCompletionSource<SteamContent.CDNAuthToken>> CDNAuthTokens { get; } = [];
    public Dictionary<uint, SteamApps.PICSProductInfoCallback.PICSProductInfo> AppInfo { get; } = [];
    public Dictionary<uint, SteamApps.PICSProductInfoCallback.PICSProductInfo> PackageInfo { get; } = [];
    public Dictionary<string, byte[]> AppBetaPasswords { get; } = [];

    public SteamClient steamClient;
    public SteamUser steamUser;
    public SteamContent steamContent;
    readonly SteamApps steamApps;
    readonly SteamCloud steamCloud;
    readonly PublishedFile steamPublishedFile;

    readonly CallbackManager callbacks;

    readonly bool authenticatedUser;
    bool bConnecting;
    bool bAborted;
    bool bExpectingDisconnectRemote;
    bool bDidDisconnect;
    bool bIsConnectionRecovery;
    int connectionBackoff;
    int seq; // more hack fixes
    AuthSession authSession;
    readonly CancellationTokenSource abortedToken = new();

    // input
    readonly SteamUser.LogOnDetails logonDetails;

    public Steam3Session(SteamUser.LogOnDetails details)
    {
        logonDetails = details;
        authenticatedUser = details.Username != null || ContentDownloader.Config.UseQrCode;

        SteamConfiguration clientConfiguration = SteamConfiguration.Create(config =>
            config
                .WithHttpClientFactory(HttpClientFactory.CreateHttpClient)
        );

        steamClient = new SteamClient(clientConfiguration);

        steamUser = steamClient.GetHandler<SteamUser>();
        steamApps = steamClient.GetHandler<SteamApps>();
        steamCloud = steamClient.GetHandler<SteamCloud>();
        SteamUnifiedMessages steamUnifiedMessages = steamClient.GetHandler<SteamUnifiedMessages>();
        steamPublishedFile = steamUnifiedMessages.CreateService<PublishedFile>();
        steamContent = steamClient.GetHandler<SteamContent>();

        callbacks = new CallbackManager(steamClient);

        callbacks.Subscribe<SteamClient.ConnectedCallback>(ConnectedCallback);
        callbacks.Subscribe<SteamClient.DisconnectedCallback>(DisconnectedCallback);
        callbacks.Subscribe<SteamUser.LoggedOnCallback>(LogOnCallback);
        callbacks.Subscribe<SteamApps.LicenseListCallback>(LicenseListCallback);

        Console.Write("Connecting to Steam3...");
        Connect();
    }

    public delegate bool WaitCondition();

    private readonly object steamLock = new();

    public bool WaitUntilCallback(Action submitter, WaitCondition waiter)
    {
        while (!bAborted && !waiter())
        {
            lock (steamLock)
            {
                submitter();
            }

            int seq = this.seq;
            do
            {
                lock (steamLock)
                {
                    callbacks.RunWaitCallbacks(TimeSpan.FromSeconds(1));
                }
            } while (!bAborted && this.seq == seq && !waiter());
        }

        return bAborted;
    }

    public bool WaitForCredentials()
    {
        if (IsLoggedOn || bAborted)
            return IsLoggedOn;

        WaitUntilCallback(() => { }, () => IsLoggedOn);

        return IsLoggedOn;
    }

    public async Task TickCallbacks()
    {
        CancellationToken token = abortedToken.Token;

        try
        {
            while (!token.IsCancellationRequested)
            {
                await callbacks.RunWaitCallbackAsync(token);
            }
        }
        catch (OperationCanceledException)
        {
            //
        }
    }

    public async Task RequestAppInfo(uint appId, bool bForce = false)
    {
        if ((AppInfo.ContainsKey(appId) && !bForce) || bAborted)
            return;

        SteamApps.PICSTokensCallback appTokens = await steamApps.PICSGetAccessTokens([appId], []);

        if (appTokens.AppTokensDenied.Contains(appId))
        {
            Console.WriteLine("Insufficient privileges to get access token for app {0}", appId);
        }

        foreach (KeyValuePair<uint, ulong> token_dict in appTokens.AppTokens)
        {
            AppTokens[token_dict.Key] = token_dict.Value;
        }

        SteamApps.PICSRequest request = new(appId);

        if (AppTokens.TryGetValue(appId, out ulong token))
        {
            request.AccessToken = token;
        }

        AsyncJobMultiple<SteamApps.PICSProductInfoCallback>.ResultSet appInfoMultiple = await steamApps.PICSGetProductInfo([request], []);

        foreach (SteamApps.PICSProductInfoCallback appInfo in appInfoMultiple.Results)
        {
            foreach (KeyValuePair<uint, SteamApps.PICSProductInfoCallback.PICSProductInfo> app_value in appInfo.Apps)
            {
                SteamApps.PICSProductInfoCallback.PICSProductInfo app = app_value.Value;

                Console.WriteLine("Got AppInfo for {0}", app.ID);
                AppInfo[app.ID] = app;
            }

            foreach (uint app in appInfo.UnknownApps)
            {
                AppInfo[app] = null;
            }
        }
    }

    public async Task RequestPackageInfo(IEnumerable<uint> packageIds)
    {
        List<uint> packages = packageIds.ToList();
        packages.RemoveAll(PackageInfo.ContainsKey);

        if (packages.Count == 0 || bAborted)
            return;

        List<SteamApps.PICSRequest> packageRequests = new();

        foreach (uint package in packages)
        {
            SteamApps.PICSRequest request = new(package);

            if (PackageTokens.TryGetValue(package, out ulong token))
            {
                request.AccessToken = token;
            }

            packageRequests.Add(request);
        }

        AsyncJobMultiple<SteamApps.PICSProductInfoCallback>.ResultSet packageInfoMultiple = await steamApps.PICSGetProductInfo([], packageRequests);

        foreach (SteamApps.PICSProductInfoCallback packageInfo in packageInfoMultiple.Results)
        {
            foreach (KeyValuePair<uint, SteamApps.PICSProductInfoCallback.PICSProductInfo> package_value in packageInfo.Packages)
            {
                SteamApps.PICSProductInfoCallback.PICSProductInfo package = package_value.Value;
                PackageInfo[package.ID] = package;
            }

            foreach (uint package in packageInfo.UnknownPackages)
            {
                PackageInfo[package] = null;
            }
        }
    }

    public async Task<bool> RequestFreeAppLicense(uint appId)
    {
        SteamApps.FreeLicenseCallback resultInfo = await steamApps.RequestFreeLicense(appId);

        return resultInfo.GrantedApps.Contains(appId);
    }

    public async Task RequestDepotKey(uint depotId, uint appid = 0)
    {
        if (DepotKeys.ContainsKey(depotId) || bAborted)
            return;

        SteamApps.DepotKeyCallback depotKey = await steamApps.GetDepotDecryptionKey(depotId, appid);

        Console.WriteLine("Got depot key for {0} result: {1}", depotKey.DepotID, depotKey.Result);

        if (depotKey.Result != EResult.OK)
        {
            Abort();
            return;
        }

        DepotKeys[depotKey.DepotID] = depotKey.DepotKey;
    }


    public async Task<ulong> GetDepotManifestRequestCodeAsync(uint depotId, uint appId, ulong manifestId, string branch)
    {
        if (bAborted)
            return 0;

        ulong requestCode = await steamContent.GetManifestRequestCode(depotId, appId, manifestId, branch);

        Console.WriteLine("Got manifest request code for {0} {1} result: {2}",
            depotId, manifestId,
            requestCode);

        return requestCode;
    }

    public async Task RequestCDNAuthToken(uint appid, uint depotid, Server server)
    {
        (uint depotid, string Host) cdnKey = (depotid, server.Host);
        TaskCompletionSource<SteamContent.CDNAuthToken> completion = new();

        if (bAborted || !CDNAuthTokens.TryAdd(cdnKey, completion))
        {
            return;
        }

        DebugLog.WriteLine(nameof(Steam3Session), $"Requesting CDN auth token for {server.Host}");

        SteamContent.CDNAuthToken cdnAuth = await steamContent.GetCDNAuthToken(appid, depotid, server.Host);

        Console.WriteLine($"Got CDN auth token for {server.Host} result: {cdnAuth.Result} (expires {cdnAuth.Expiration})");

        if (cdnAuth.Result != EResult.OK)
        {
            return;
        }

        completion.TrySetResult(cdnAuth);
    }

    public async Task CheckAppBetaPassword(uint appid, string password)
    {
        SteamApps.CheckAppBetaPasswordCallback appPassword = await steamApps.CheckAppBetaPassword(appid, password);

        Console.WriteLine("Retrieved {0} beta keys with result: {1}", appPassword.BetaPasswords.Count, appPassword.Result);

        foreach (KeyValuePair<string, byte[]> entry in appPassword.BetaPasswords)
        {
            AppBetaPasswords[entry.Key] = entry.Value;
        }
    }

    public async Task<PublishedFileDetails> GetPublishedFileDetails(uint appId, PublishedFileID pubFile)
    {
        CPublishedFile_GetDetails_Request pubFileRequest = new() { appid = appId };
        pubFileRequest.publishedfileids.Add(pubFile);

        SteamUnifiedMessages.ServiceMethodResponse<CPublishedFile_GetDetails_Response> details = await steamPublishedFile.GetDetails(pubFileRequest);

        if (details.Result == EResult.OK)
        {
            return details.Body.publishedfiledetails.FirstOrDefault();
        }

        throw new Exception($"EResult {(int)details.Result} ({details.Result}) while retrieving file details for pubfile {pubFile}.");
    }


    public async Task<SteamCloud.UGCDetailsCallback> GetUGCDetails(UGCHandle ugcHandle)
    {
        SteamCloud.UGCDetailsCallback callback = await steamCloud.RequestUGCDetails(ugcHandle);

        if (callback.Result == EResult.OK)
        {
            return callback;
        }
        else if (callback.Result == EResult.FileNotFound)
        {
            return null;
        }

        throw new Exception($"EResult {(int)callback.Result} ({callback.Result}) while retrieving UGC details for {ugcHandle}.");
    }

    private void ResetConnectionFlags()
    {
        bExpectingDisconnectRemote = false;
        bDidDisconnect = false;
        bIsConnectionRecovery = false;
    }

    void Connect()
    {
        bAborted = false;
        bConnecting = true;
        connectionBackoff = 0;
        authSession = null;

        ResetConnectionFlags();
        steamClient.Connect();
    }

    private void Abort(bool sendLogOff = true)
    {
        Disconnect(sendLogOff);
    }

    public void Disconnect(bool sendLogOff = true)
    {
        if (sendLogOff)
        {
            steamUser.LogOff();
        }

        bAborted = true;
        bConnecting = false;
        bIsConnectionRecovery = false;
        abortedToken.Cancel();
        steamClient.Disconnect();

        Ansi.Progress(Ansi.ProgressState.Hidden);

        // flush callbacks until our disconnected event
        while (!bDidDisconnect)
        {
            callbacks.RunWaitAllCallbacks(TimeSpan.FromMilliseconds(100));
        }
    }

    private void Reconnect()
    {
        bIsConnectionRecovery = true;
        steamClient.Disconnect();
    }

    private async void ConnectedCallback(SteamClient.ConnectedCallback connected)
    {
        Console.WriteLine(" Done!");
        bConnecting = false;

        // Update our tracking so that we don't time out, even if we need to reconnect multiple times,
        // e.g. if the authentication phase takes a while and therefore multiple connections.
        connectionBackoff = 0;

        if (!authenticatedUser)
        {
            Console.Write("Logging anonymously into Steam3...");
            steamUser.LogOnAnonymous();
        }
        else
        {
            if (logonDetails.Username != null)
            {
                Console.WriteLine("Logging '{0}' into Steam3...", logonDetails.Username);
            }

            if (authSession is null)
            {
                if (logonDetails.Username != null && logonDetails.Password != null && logonDetails.AccessToken is null)
                {
                    try
                    {
                        _ = AccountSettingsStore.Instance.GuardData.TryGetValue(logonDetails.Username, out string guarddata);
                        authSession = await steamClient.Authentication.BeginAuthSessionViaCredentialsAsync(new AuthSessionDetails
                        {
                            Username = logonDetails.Username,
                            Password = logonDetails.Password,
                            IsPersistentSession = ContentDownloader.Config.RememberPassword,
                            GuardData = guarddata,
                            Authenticator = new UserConsoleAuthenticator(),
                        });
                    }
                    catch (TaskCanceledException)
                    {
                        return;
                    }
                    catch (Exception ex)
                    {
                        Console.Error.WriteLine("Failed to authenticate with Steam: " + ex.Message);
                        Abort(false);
                        return;
                    }
                }
                else if (logonDetails.AccessToken is null && ContentDownloader.Config.UseQrCode)
                {
                    Console.WriteLine("Logging in with QR code...");

                    try
                    {
                        QrAuthSession session = await steamClient.Authentication.BeginAuthSessionViaQRAsync(new AuthSessionDetails
                        {
                            IsPersistentSession = ContentDownloader.Config.RememberPassword,
                            Authenticator = new UserConsoleAuthenticator(),
                        });

                        authSession = session;

                        // Steam will periodically refresh the challenge url, so we need a new QR code.
                        session.ChallengeURLChanged = () =>
                        {
                            Console.WriteLine();
                            Console.WriteLine("The QR code has changed:");

                            DisplayQrCode(session.ChallengeURL);
                        };

                        // Draw initial QR code immediately
                        DisplayQrCode(session.ChallengeURL);
                    }
                    catch (TaskCanceledException)
                    {
                        return;
                    }
                    catch (Exception ex)
                    {
                        Console.Error.WriteLine("Failed to authenticate with Steam: " + ex.Message);
                        Abort(false);
                        return;
                    }
                }
            }

            if (authSession != null)
            {
                try
                {
                    AuthPollResult result = await authSession.PollingWaitForResultAsync();

                    logonDetails.Username = result.AccountName;
                    logonDetails.Password = null;
                    logonDetails.AccessToken = result.RefreshToken;

                    if (result.NewGuardData != null)
                    {
                        AccountSettingsStore.Instance.GuardData[result.AccountName] = result.NewGuardData;
                    }
                    else
                    {
                        AccountSettingsStore.Instance.GuardData.Remove(result.AccountName);
                    }
                    AccountSettingsStore.Instance.LoginTokens[result.AccountName] = result.RefreshToken;
                    AccountSettingsStore.Save();
                }
                catch (TaskCanceledException)
                {
                    return;
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine("Failed to authenticate with Steam: " + ex.Message);
                    Abort(false);
                    return;
                }

                authSession = null;
            }

            steamUser.LogOn(logonDetails);
        }
    }

    private void DisconnectedCallback(SteamClient.DisconnectedCallback disconnected)
    {
        bDidDisconnect = true;

        DebugLog.WriteLine(nameof(Steam3Session), $"Disconnected: bIsConnectionRecovery = {bIsConnectionRecovery}, UserInitiated = {disconnected.UserInitiated}, bExpectingDisconnectRemote = {bExpectingDisconnectRemote}");

        // When recovering the connection, we want to reconnect even if the remote disconnects us
        if (!bIsConnectionRecovery && (disconnected.UserInitiated || bExpectingDisconnectRemote))
        {
            Console.WriteLine("Disconnected from Steam");

            // Any operations outstanding need to be aborted
            bAborted = true;
        }
        else if (connectionBackoff >= 10)
        {
            Console.WriteLine("Could not connect to Steam after 10 tries");
            Abort(false);
        }
        else if (!bAborted)
        {
            connectionBackoff += 1;

            if (bConnecting)
            {
                Console.WriteLine($"Connection to Steam failed. Trying again (#{connectionBackoff})...");
            }
            else
            {
                Console.WriteLine("Lost connection to Steam. Reconnecting");
            }

            Thread.Sleep(1000 * connectionBackoff);

            // Any connection related flags need to be reset here to match the state after Connect
            ResetConnectionFlags();
            steamClient.Connect();
        }
    }

    private void LogOnCallback(SteamUser.LoggedOnCallback loggedOn)
    {
        bool isSteamGuard = loggedOn.Result == EResult.AccountLogonDenied;
        bool is2FA = loggedOn.Result == EResult.AccountLoginDeniedNeedTwoFactor;
        bool isAccessToken = ContentDownloader.Config.RememberPassword && logonDetails.AccessToken != null &&
                             loggedOn.Result is EResult.InvalidPassword
                                 or EResult.InvalidSignature
                                 or EResult.AccessDenied
                                 or EResult.Expired
                                 or EResult.Revoked;

        if (isSteamGuard || is2FA || isAccessToken)
        {
            bExpectingDisconnectRemote = true;
            Abort(false);

            if (!isAccessToken)
            {
                Console.WriteLine("This account is protected by Steam Guard.");
            }

            if (is2FA)
            {
                do
                {
                    Console.Write("Please enter your 2 factor auth code from your authenticator app: ");
                    logonDetails.TwoFactorCode = Console.ReadLine();
                } while (string.Empty == logonDetails.TwoFactorCode);
            }
            else if (isAccessToken)
            {
                AccountSettingsStore.Instance.LoginTokens.Remove(logonDetails.Username);
                AccountSettingsStore.Save();

                // TODO: Handle gracefully by falling back to password prompt?
                Console.WriteLine($"Access token was rejected ({loggedOn.Result}).");
                Abort(false);
                return;
            }
            else
            {
                do
                {
                    Console.Write("Please enter the authentication code sent to your email address: ");
                    logonDetails.AuthCode = Console.ReadLine();
                } while (string.Empty == logonDetails.AuthCode);
            }

            Console.Write("Retrying Steam3 connection...");
            Connect();

            return;
        }

        if (loggedOn.Result == EResult.TryAnotherCM)
        {
            Console.Write("Retrying Steam3 connection (TryAnotherCM)...");

            Reconnect();

            return;
        }

        if (loggedOn.Result == EResult.ServiceUnavailable)
        {
            Console.WriteLine("Unable to login to Steam3: {0}", loggedOn.Result);
            Abort(false);

            return;
        }

        if (loggedOn.Result != EResult.OK)
        {
            Console.WriteLine("Unable to login to Steam3: {0}", loggedOn.Result);
            Abort();

            return;
        }

        Console.WriteLine(" Done!");

        seq++;
        IsLoggedOn = true;

        if (ContentDownloader.Config.CellID == 0)
        {
            Console.WriteLine("Using Steam3 suggested CellID: " + loggedOn.CellID);
            ContentDownloader.Config.CellID = (int)loggedOn.CellID;
        }
    }

    private void LicenseListCallback(SteamApps.LicenseListCallback licenseList)
    {
        if (licenseList.Result != EResult.OK)
        {
            Console.WriteLine("Unable to get license list: {0} ", licenseList.Result);
            Abort();

            return;
        }

        Console.WriteLine("Got {0} licenses for account!", licenseList.LicenseList.Count);
        Licenses = licenseList.LicenseList;

        foreach (SteamApps.LicenseListCallback.License license in licenseList.LicenseList)
        {
            if (license.AccessToken > 0)
            {
                PackageTokens.TryAdd(license.PackageID, license.AccessToken);
            }
        }
    }

    private static void DisplayQrCode(string challengeUrl)
    {
        // Encode the link as a QR code
        using QRCodeGenerator qrGenerator = new();
        QRCodeData qrCodeData = qrGenerator.CreateQrCode(challengeUrl, QRCodeGenerator.ECCLevel.L);
        using AsciiQRCode qrCode = new(qrCodeData);
        string qrCodeAsAsciiArt = qrCode.GetGraphic(1, drawQuietZones: false);

        Console.WriteLine("Use the Steam Mobile App to sign in with this QR code:");
        Console.WriteLine(qrCodeAsAsciiArt);
    }
}