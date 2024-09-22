using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using QRCoder;
using SteamKit2;
using SteamKit2.Authentication;
using SteamKit2.Internal;

namespace DepotDownloader
{
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
        public Dictionary<uint, SteamApps.PICSProductInfoCallback.PICSProductInfo> AppInfo { get; } = [];
        public Dictionary<uint, SteamApps.PICSProductInfoCallback.PICSProductInfo> PackageInfo { get; } = [];
        public Dictionary<string, byte[]> AppBetaPasswords { get; } = [];

        public SteamClient steamClient;
        public SteamUser steamUser;
        public SteamContent steamContent;
        readonly SteamApps steamApps;
        readonly SteamCloud steamCloud;
        readonly SteamUnifiedMessages.UnifiedService<IPublishedFile> steamPublishedFile;

        readonly CallbackManager callbacks;

        readonly bool authenticatedUser;
        bool bConnected;
        bool bConnecting;
        bool bAborted;
        bool bExpectingDisconnectRemote;
        bool bDidDisconnect;
        bool bIsConnectionRecovery;
        int connectionBackoff;
        int seq; // more hack fixes
        DateTime connectTime;
        AuthSession authSession;

        // input
        readonly SteamUser.LogOnDetails logonDetails;

        static readonly TimeSpan STEAM3_TIMEOUT = TimeSpan.FromSeconds(30);


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
            steamPublishedFile = steamUnifiedMessages.CreateService<IPublishedFile>();
            steamContent = steamClient.GetHandler<SteamContent>();

            callbacks = new CallbackManager(steamClient);

            callbacks.Subscribe<SteamClient.ConnectedCallback>(ConnectedCallback);
            callbacks.Subscribe<SteamClient.DisconnectedCallback>(DisconnectedCallback);
            callbacks.Subscribe<SteamUser.LoggedOnCallback>(LogOnCallback);
            callbacks.Subscribe<SteamApps.LicenseListCallback>(LicenseListCallback);

            DepotDownloaderHelper.Logger.Info("Connecting to Steam3...");
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
                        WaitForCallbacks();
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

        public void RequestAppInfo(uint appId, bool bForce = false)
        {
            if ((AppInfo.ContainsKey(appId) && !bForce) || bAborted)
                return;

            bool completed = false;
            Action<SteamApps.PICSTokensCallback> cbMethodTokens = appTokens =>
            {
                completed = true;
                if (appTokens.AppTokensDenied.Contains(appId))
                {
                    DepotDownloaderHelper.Logger.Error("Insufficient privileges to get access token for app {0}", appId);
                }

                foreach (KeyValuePair<uint, ulong> token_dict in appTokens.AppTokens)
                {
                    AppTokens[token_dict.Key] = token_dict.Value;
                }
            };

            WaitUntilCallback(() =>
            {
                callbacks.Subscribe(steamApps.PICSGetAccessTokens(new List<uint> { appId }, new List<uint>()), cbMethodTokens);
            }, () => completed);

            completed = false;
            Action<SteamApps.PICSProductInfoCallback> cbMethod = appInfo =>
            {
                completed = !appInfo.ResponsePending;

                foreach (KeyValuePair<uint, SteamApps.PICSProductInfoCallback.PICSProductInfo> app_value in appInfo.Apps)
                {
                    SteamApps.PICSProductInfoCallback.PICSProductInfo app = app_value.Value;

                    DepotDownloaderHelper.Logger.Info("Got AppInfo for {0}", app.ID);
                    AppInfo[app.ID] = app;
                }

                foreach (uint app in appInfo.UnknownApps)
                {
                    AppInfo[app] = null;
                }
            };

            SteamApps.PICSRequest request = new(appId);
            if (AppTokens.TryGetValue(appId, out ulong token))
            {
                request.AccessToken = token;
            }

            WaitUntilCallback(() =>
            {
                callbacks.Subscribe(steamApps.PICSGetProductInfo(new List<SteamApps.PICSRequest> { request }, new List<SteamApps.PICSRequest>()), cbMethod);
            }, () => completed);
        }

        public void RequestPackageInfo(IEnumerable<uint> packageIds)
        {
            List<uint> packages = packageIds.ToList();
            packages.RemoveAll(pid => PackageInfo.ContainsKey(pid));

            if (packages.Count == 0 || bAborted)
                return;

            bool completed = false;
            Action<SteamApps.PICSProductInfoCallback> cbMethod = packageInfo =>
            {
                completed = !packageInfo.ResponsePending;

                foreach (KeyValuePair<uint, SteamApps.PICSProductInfoCallback.PICSProductInfo> package_value in packageInfo.Packages)
                {
                    SteamApps.PICSProductInfoCallback.PICSProductInfo package = package_value.Value;
                    PackageInfo[package.ID] = package;
                }

                foreach (uint package in packageInfo.UnknownPackages)
                {
                    PackageInfo[package] = null;
                }
            };

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

            WaitUntilCallback(() =>
            {
                callbacks.Subscribe(steamApps.PICSGetProductInfo(new List<SteamApps.PICSRequest>(), packageRequests), cbMethod);
            }, () => completed);
        }

        public bool RequestFreeAppLicense(uint appId)
        {
            bool success = false;
            bool completed = false;
            Action<SteamApps.FreeLicenseCallback> cbMethod = resultInfo =>
            {
                completed = true;
                success = resultInfo.GrantedApps.Contains(appId);
            };

            WaitUntilCallback(() =>
            {
                callbacks.Subscribe(steamApps.RequestFreeLicense(appId), cbMethod);
            }, () => completed);

            return success;
        }

        public void RequestDepotKey(uint depotId, uint appid = 0)
        {
            if (DepotKeys.ContainsKey(depotId) || bAborted)
                return;

            bool completed = false;

            Action<SteamApps.DepotKeyCallback> cbMethod = depotKey =>
            {
                completed = true;
                DepotDownloaderHelper.Logger.Info("Got depot key for {0} result: {1}", depotKey.DepotID, depotKey.Result);

                if (depotKey.Result != EResult.OK)
                {
                    Abort();
                    return;
                }

                DepotKeys[depotKey.DepotID] = depotKey.DepotKey;
            };

            WaitUntilCallback(() =>
            {
                callbacks.Subscribe(steamApps.GetDepotDecryptionKey(depotId, appid), cbMethod);
            }, () => completed);
        }


        public async Task<ulong> GetDepotManifestRequestCodeAsync(uint depotId, uint appId, ulong manifestId, string branch)
        {
            if (bAborted)
                return 0;

            ulong requestCode = await steamContent.GetManifestRequestCode(depotId, appId, manifestId, branch);

            DepotDownloaderHelper.Logger.Info("Got manifest request code for {0} {1} result: {2}",
                depotId, manifestId,
                requestCode);

            return requestCode;
        }

        public void CheckAppBetaPassword(uint appid, string password)
        {
            bool completed = false;
            Action<SteamApps.CheckAppBetaPasswordCallback> cbMethod = appPassword =>
            {
                completed = true;

                DepotDownloaderHelper.Logger.Info("Retrieved {0} beta keys with result: {1}", 
                    appPassword.BetaPasswords.Count, appPassword.Result);

                foreach (KeyValuePair<string, byte[]> entry in appPassword.BetaPasswords)
                {
                    AppBetaPasswords[entry.Key] = entry.Value;
                }
            };

            WaitUntilCallback(() =>
            {
                callbacks.Subscribe(steamApps.CheckAppBetaPassword(appid, password), cbMethod);
            }, () => completed);
        }

        public PublishedFileDetails GetPublishedFileDetails(uint appId, PublishedFileID pubFile)
        {
            CPublishedFile_GetDetails_Request pubFileRequest = new() { appid = appId };
            pubFileRequest.publishedfileids.Add(pubFile);

            bool completed = false;
            PublishedFileDetails details = null;

            Action<SteamUnifiedMessages.ServiceMethodResponse> cbMethod = callback =>
            {
                completed = true;
                if (callback.Result == EResult.OK)
                {
                    CPublishedFile_GetDetails_Response response = callback.GetDeserializedResponse<CPublishedFile_GetDetails_Response>();
                    details = response.publishedfiledetails.FirstOrDefault();
                }
                else
                {
                    DepotDownloaderHelper.Logger.Error("EResult {0} ({1}) while retrieving file details for pubfile {2}.",
                        (int)callback.Result, callback.Result, pubFile);
                    
                    throw new Exception($"EResult {(int)callback.Result} ({callback.Result}) while retrieving file details for pubfile {pubFile}.");
                }
            };

            WaitUntilCallback(() =>
            {
                callbacks.Subscribe(steamPublishedFile.SendMessage(api => api.GetDetails(pubFileRequest)), cbMethod);
            }, () => completed);

            return details;
        }


        public SteamCloud.UGCDetailsCallback GetUGCDetails(UGCHandle ugcHandle)
        {
            bool completed = false;
            SteamCloud.UGCDetailsCallback details = null;

            Action<SteamCloud.UGCDetailsCallback> cbMethod = callback =>
            {
                completed = true;
                if (callback.Result == EResult.OK)
                {
                    details = callback;
                }
                else if (callback.Result == EResult.FileNotFound)
                {
                    details = null;
                }
                else
                {
                    DepotDownloaderHelper.Logger.Error("EResult {0} ({1}) while retrieving UGC details for {2}.",
                        (int)callback.Result, callback.Result, ugcHandle);
                    
                    throw new Exception($"EResult {(int)callback.Result} ({callback.Result}) while retrieving UGC details for {ugcHandle}.");
                }
            };

            WaitUntilCallback(() =>
            {
                callbacks.Subscribe(steamCloud.RequestUGCDetails(ugcHandle), cbMethod);
            }, () => completed);

            return details;
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
            bConnected = false;
            bConnecting = true;
            connectionBackoff = 0;
            authSession = null;

            ResetConnectionFlags();

            connectTime = DateTime.Now;
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
            bConnected = false;
            bConnecting = false;
            bIsConnectionRecovery = false;
            steamClient.Disconnect();

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

        private void WaitForCallbacks()
        {
            callbacks.RunWaitCallbacks(TimeSpan.FromSeconds(1));

            TimeSpan diff = DateTime.Now - connectTime;

            if (diff > STEAM3_TIMEOUT && !bConnected)
            {
                DepotDownloaderHelper.Logger.Error("Timeout connecting to Steam3.");
                Abort();
            }
        }

        private async void ConnectedCallback(SteamClient.ConnectedCallback connected)
        {
            DepotDownloaderHelper.Logger.Info("Done!");
            bConnecting = false;
            bConnected = true;

            // Update our tracking so that we don't time out, even if we need to reconnect multiple times,
            // e.g. if the authentication phase takes a while and therefore multiple connections.
            connectTime = DateTime.Now;
            connectionBackoff = 0;

            if (!authenticatedUser)
            {
                DepotDownloaderHelper.Logger.Info("Logging anonymously into Steam3...");
                steamUser.LogOnAnonymous();
            }
            else
            {
                if (logonDetails.Username != null)
                {
                    DepotDownloaderHelper.Logger.Info("Logging '{0}' into Steam3...", logonDetails.Username);
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
                            DepotDownloaderHelper.Logger.Error("Failed to authenticate with Steam: {0}", 
                                ex.Message);
                            
                            Abort(false);
                            return;
                        }
                    }
                    else if (logonDetails.AccessToken is null && ContentDownloader.Config.UseQrCode)
                    {
                        DepotDownloaderHelper.Logger.Info("Logging in with QR code...");

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
                                DepotDownloaderHelper.Logger.Info("The QR code has changed:");

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
                            DepotDownloaderHelper.Logger.Error("Failed to authenticate with Steam: {0}", 
                                ex.Message);
                            
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
                        DepotDownloaderHelper.Logger.Error("Failed to authenticate with Steam: {0}",
                            ex.Message);
                        
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

            DepotDownloaderHelper.Logger.Info($"Disconnected: bIsConnectionRecovery = {bIsConnectionRecovery}, UserInitiated = {disconnected.UserInitiated}, bExpectingDisconnectRemote = {bExpectingDisconnectRemote}");

            // When recovering the connection, we want to reconnect even if the remote disconnects us
            if (!bIsConnectionRecovery && (disconnected.UserInitiated || bExpectingDisconnectRemote))
            {
                DepotDownloaderHelper.Logger.Info("Disconnected from Steam");

                // Any operations outstanding need to be aborted
                bAborted = true;
            }
            else if (connectionBackoff >= 10)
            {
                DepotDownloaderHelper.Logger.Error("Could not connect to Steam after 10 tries");
                Abort(false);
            }
            else if (!bAborted)
            {
                DepotDownloaderHelper.Logger.Warn(bConnecting
                    ? "Connection to Steam failed. Trying again"
                    : "Lost connection to Steam. Reconnecting");

                Thread.Sleep(1000 * ++connectionBackoff);

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
                    DepotDownloaderHelper.Logger.Error("This account is protected by Steam Guard.");
                }

                if (is2FA)
                {
                    do
                    {
                        DepotDownloaderHelper.Logger.Info("Please enter your 2 factor auth code from your authenticator app: ");
                        logonDetails.TwoFactorCode = Console.ReadLine();
                    } while (string.Empty == logonDetails.TwoFactorCode);
                }
                else if (isAccessToken)
                {
                    AccountSettingsStore.Instance.LoginTokens.Remove(logonDetails.Username);
                    AccountSettingsStore.Save();

                    // TODO: Handle gracefully by falling back to password prompt?
                    DepotDownloaderHelper.Logger.Info($"Access token was rejected ({loggedOn.Result}).");
                    Abort(false);
                    return;
                }
                else
                {
                    do
                    {
                        DepotDownloaderHelper.Logger.Info("Please enter the authentication code sent to your email address: ");
                        logonDetails.AuthCode = Console.ReadLine();
                    } while (string.Empty == logonDetails.AuthCode);
                }

                DepotDownloaderHelper.Logger.Info("Retrying Steam3 connection...");
                Connect();

                return;
            }

            if (loggedOn.Result == EResult.TryAnotherCM)
            {
                DepotDownloaderHelper.Logger.Info("Retrying Steam3 connection (TryAnotherCM)...");

                Reconnect();

                return;
            }

            if (loggedOn.Result == EResult.ServiceUnavailable)
            {
                DepotDownloaderHelper.Logger.Error("Unable to login to Steam3: {0}", loggedOn.Result);
                Abort(false);

                return;
            }

            if (loggedOn.Result != EResult.OK)
            {
                DepotDownloaderHelper.Logger.Error("Unable to login to Steam3: {0}", loggedOn.Result);
                Abort();

                return;
            }

            DepotDownloaderHelper.Logger.Info("Done!");

            seq++;
            IsLoggedOn = true;

            if (ContentDownloader.Config.CellID == 0)
            {
                DepotDownloaderHelper.Logger.Info("Using Steam3 suggested CellID: " + loggedOn.CellID);
                ContentDownloader.Config.CellID = (int)loggedOn.CellID;
            }
        }

        private void LicenseListCallback(SteamApps.LicenseListCallback licenseList)
        {
            if (licenseList.Result != EResult.OK)
            {
                DepotDownloaderHelper.Logger.Error("Unable to get license list: {0} ", licenseList.Result);
                Abort();

                return;
            }

            DepotDownloaderHelper.Logger.Info("Got {0} licenses for account!", licenseList.LicenseList.Count);
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

            DepotDownloaderHelper.Logger.Info("Use the Steam Mobile App to sign in with this QR code:");
            DepotDownloaderHelper.Logger.Info(qrCodeAsAsciiArt);
        }
    }
}
