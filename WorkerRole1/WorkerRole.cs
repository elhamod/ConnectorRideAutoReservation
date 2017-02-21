using HtmlAgilityPack;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using Microsoft.WindowsAzure.ServiceRuntime;
using Microsoft.ApplicationInsights;
using Microsoft.ApplicationInsights.DataContracts;
using Microsoft.Azure.KeyVault;
using Microsoft.ServiceBus.Messaging;

namespace WorkerRole1
{
    public class WorkerRole : RoleEntryPoint
    {
        private readonly CancellationTokenSource cancellationTokenSource = new CancellationTokenSource();
        private readonly ManualResetEvent runCompleteEvent = new ManualResetEvent(false);

        private const string RequestVerificationToken = "__RequestVerificationToken";
        private const string domainUrl = "https://www.connectorride.com";
        private const string loginUrl = domainUrl + "/Account/Login";
        private const string bookStandbyUrl = domainUrl + "/Flex/BookFlexOrStandby";

        private TelemetryClient telemetryClient;
        private GetTokenResult getTokenResult;
        private CookieContainer cookieContainer;

        struct GetTokenResult
        {
            public string antiForgeryCookie;
            public string token;
        }

        public override void Run()
        {
            ServicePointManager.ServerCertificateValidationCallback += (o, c, ch, er) => true;
            Trace.TraceInformation("ConnectorRide worker is running");

            try
            {
                this.RunAsync(this.cancellationTokenSource.Token).Wait();
            }
            finally
            {
                this.runCompleteEvent.Set();
            }
        }

        public override bool OnStart()
        {
            // Set the maximum number of concurrent connections
            ServicePointManager.DefaultConnectionLimit = 12;

            // For information on handling configuration changes
            // see the MSDN topic at https://go.microsoft.com/fwlink/?LinkId=166357.

            bool result = base.OnStart();

            Trace.TraceInformation("ConnectorRide worker has been started");

            return result;
        }

        public override void OnStop()
        {
            Trace.TraceInformation("ConnectorRide worker is stopping");

            this.cancellationTokenSource.Cancel();
            this.runCompleteEvent.WaitOne();

            base.OnStop();

            Trace.TraceInformation("ConnectorRide worker has stopped");
        }

        private void SendTelemetry(string url, string name, string responseCode, Dictionary<string, string> properties)
        {
            RequestTelemetry requestTelemetry = new RequestTelemetry();
            requestTelemetry.Url = new Uri(url);
            requestTelemetry.ResponseCode = responseCode;
            requestTelemetry.Name = name;
            requestTelemetry.Properties.Concat(properties);
            telemetryClient.TrackRequest(requestTelemetry);
            telemetryClient.Flush();
        }

        private void GetToken()
        {
            getTokenResult = new GetTokenResult();

            HttpWebRequest request = WebRequest.CreateHttp(loginUrl);
            request.Method = "Get";
            HttpWebResponse response = (HttpWebResponse)request.GetResponse();
            string setCookie = response.Headers.GetValues("Set-Cookie")[0];
            Dictionary<string, string> setCookieDictionary = setCookie.Split(';').ToDictionary<string, string, string>(i => i.Split('=')[0], i => i.Split('=').Length > 1 ? i.Split('=')[1] : null);
            getTokenResult.antiForgeryCookie = setCookieDictionary.First().Value;
            Stream dataStream = response.GetResponseStream();
            StreamReader reader = new StreamReader(dataStream);
            string responseFromServer = reader.ReadToEnd();
            HtmlDocument doc = new HtmlDocument();
            doc.LoadHtml(responseFromServer);
            HtmlNode requestVerificationTokenNode = doc.DocumentNode.Descendants().Where(node => node.GetAttributeValue("name", "Error") == RequestVerificationToken).First();
            getTokenResult.token = requestVerificationTokenNode.GetAttributeValue("value", "Error");

            var properties = new Dictionary<string, string>();
            properties.Add("AntiForgeryCookie", getTokenResult.antiForgeryCookie);
            SendTelemetry(loginUrl, "GetToken", response.StatusCode.ToString(), properties);
        }

        private void SendRequest(string url, string requestName, Dictionary<string, string> requestContentDictionary, Dictionary<string, string> telemtryDictionary)
        {
            HttpWebRequest request = WebRequest.CreateHttp(url);
            request.Method = "Post";
            request.ContentType = "application/x-www-form-urlencoded";
            request.CookieContainer = cookieContainer;
            Stream signInStream = request.GetRequestStream();
            string signInContentDictionaryString = string.Join("&", requestContentDictionary.Select(x => x.Key + "=" + x.Value).ToArray());
            byte[] signInContentBytes = Encoding.ASCII.GetBytes(signInContentDictionaryString);
            signInStream.Write(signInContentBytes, 0, signInContentBytes.Length);
            signInStream.Close();
            HttpWebResponse response = (HttpWebResponse)request.GetResponse();

            SendTelemetry(url, requestName, response.StatusCode.ToString(), telemtryDictionary);
        }

        private void CreateCookieContainer()
        {
            Uri target = new Uri(loginUrl);
            cookieContainer = new CookieContainer();
            cookieContainer.Add(new Cookie(RequestVerificationToken, getTokenResult.antiForgeryCookie) { Domain = target.Host });
        }

        private async Task RunAsync(CancellationToken cancellationToken)
        {
            try
            {
                // Grab secrets
                var keyVaultClient = new KeyVaultClient(new KeyVaultClient.AuthenticationCallback(KeyVaultAuthHelper.GetAccessToken));
                //var keyVaultClient = new KeyVaultClient(AuthenticateVault); // In case we use key instead of cert
                var secretsVault = RoleEnvironment.GetConfigurationSettingValue("SecretsVault");
                var instrumentationkey = await keyVaultClient.GetSecretAsync(secretsVault, "instrumentationkey");
                var username = await keyVaultClient.GetSecretAsync(secretsVault, "username");
                var password = await keyVaultClient.GetSecretAsync(secretsVault, "password");
                var serviceBusConnectionString = await keyVaultClient.GetSecretAsync(secretsVault, "ServiceBusConnectionString");

                // Setup telemetry
                telemetryClient = new TelemetryClient();
                telemetryClient.InstrumentationKey = instrumentationkey.Value;

                // Listen to Scheduler
                var queueName = RoleEnvironment.GetConfigurationSettingValue("ServiceBusQueueName");
                var client = QueueClient.CreateFromConnectionString(serviceBusConnectionString.Value, queueName);
                OnMessageOptions options = new OnMessageOptions();
                options.AutoComplete = true; // Indicates if the message-pump should call complete on messages after the callback has completed processing.
                options.MaxConcurrentCalls = 1; // Indicates the maximum number of concurrent calls to the callback the pump should initiate 
                client.OnMessage((receivedMessage) => // Initiates the message pump and callback is invoked for each message that is recieved, calling close on the client will stop the pump.
                {
                    try
                    {
                        var eventTelemetry = new EventTelemetry("SchedulingMessageReseived");
                        telemetryClient.TrackEvent(eventTelemetry);
                        telemetryClient.Flush();

                        // get token
                        GetToken();
                        CreateCookieContainer();

                        // sign in
                        Dictionary<string, string> signInContentDictionary = new Dictionary<string, string>();
                        signInContentDictionary.Add(RequestVerificationToken, getTokenResult.token);
                        signInContentDictionary.Add("ComputerTypes", "PublicComputer");
                        signInContentDictionary.Add("UserName", username.Value);
                        signInContentDictionary.Add("Password", password.Value);
                        var telemetryProperties = new Dictionary<string, string>();
                        telemetryProperties.Add("RequestVerificationToken", getTokenResult.token);
                        SendRequest(loginUrl, "Login", signInContentDictionary, telemetryProperties);

                        // Book
                        Dictionary<string, string> bookingStandbyDictionary = new Dictionary<string, string>();
                        DateTime reservationDateTime = DateTime.Today.AddDays(14);
                        reservationDateTime = reservationDateTime.Date + new TimeSpan(4, 29, 0); // we book 14 weeks in advance
                        bookingStandbyDictionary.Add("RouteID", "12770"); // This needs to be automated
                        bookingStandbyDictionary.Add("OriginalDateTime", HttpUtility.UrlEncode(String.Format("{0:G}", reservationDateTime)));
                        bookingStandbyDictionary.Add("Bike", "False");
                        bookingStandbyDictionary.Add("Park", "False");
                        bookingStandbyDictionary.Add("WC", "False");
                        bookingStandbyDictionary.Add("PickID", "1");
                        bookingStandbyDictionary.Add("DropID", "63");
                        bookingStandbyDictionary.Add("CancelDoubleBooking", "False");
                        bookingStandbyDictionary.Add("OldFlexID", "0");
                        bookingStandbyDictionary.Add("AMorPMValue", "PM");
                        bookingStandbyDictionary.Add("rbScheds", "118|42991|False|False|True|S");
                        bookingStandbyDictionary.Add("X-Requested-With", "XMLHttpRequest");
                        telemetryProperties = new Dictionary<string, string>();
                        SendRequest(bookStandbyUrl, "BookFlexOrStandby", bookingStandbyDictionary, telemetryProperties);
                    }
                    catch (Exception err)
                    {
                        Trace.TraceError("Error processing scheduling message", err);
                        LogErrorTelemetry(err);
                    }
                }, options);
            }
            catch (Exception err)
            {
                Trace.TraceError("Error running ConnectorRide worker", err);
                LogErrorTelemetry(err);
            }

            cancellationToken.WaitHandle.WaitOne();
        }

        private void LogErrorTelemetry(Exception err)
        {
            if (telemetryClient != null && !string.IsNullOrEmpty(telemetryClient.InstrumentationKey))
            {
                var exceptionTelemetry = new ExceptionTelemetry(err);
                telemetryClient.TrackException(exceptionTelemetry);
                telemetryClient.Flush();
            }
        }
    }
}
