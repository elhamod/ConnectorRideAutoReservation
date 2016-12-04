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
using Microsoft.WindowsAzure;
using Microsoft.WindowsAzure.Diagnostics;
using Microsoft.WindowsAzure.ServiceRuntime;
using Microsoft.WindowsAzure.Storage;
using Microsoft.ApplicationInsights;
using Microsoft.ApplicationInsights.DataContracts;

namespace WorkerRole1
{
    public class WorkerRole : RoleEntryPoint
    {
        private readonly CancellationTokenSource cancellationTokenSource = new CancellationTokenSource();
        private readonly ManualResetEvent runCompleteEvent = new ManualResetEvent(false);

        public override void Run()
        {
            ServicePointManager.ServerCertificateValidationCallback += (o, c, ch, er) => true;
            Trace.TraceInformation("WorkerRole1 is running");

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

            Trace.TraceInformation("WorkerRole1 has been started");

            return result;
        }

        public override void OnStop()
        {
            Trace.TraceInformation("WorkerRole1 is stopping");

            this.cancellationTokenSource.Cancel();
            this.runCompleteEvent.WaitOne();

            base.OnStop();

            Trace.TraceInformation("WorkerRole1 has stopped");
        }

        private async Task RunAsync(CancellationToken cancellationToken)
        {
                TelemetryClient telemetryClient = new TelemetryClient();
                telemetryClient.InstrumentationKey = RoleEnvironment.GetConfigurationSettingValue("APPINSIGHTS_INSTRUMENTATIONKEY");
            
                string RequestVerificationToken = "__RequestVerificationToken";
                string domainUrl = "https://www.connectorride.com";
                string loginUrl = domainUrl + "/Account/Login";
                string bookUrl = domainUrl + "/Flex/BookFlex";

            // TODO: Replace the following with your own logic.
            while (!cancellationToken.IsCancellationRequested)
            {
                // get token
                HttpWebRequest request = WebRequest.CreateHttp(loginUrl);
                request.Method = "Get";
                HttpWebResponse response = (HttpWebResponse)request.GetResponse();
                string setCookie = response.Headers.GetValues("Set-Cookie")[0];
                Dictionary<string, string> setCookieDictionary = setCookie.Split(';').ToDictionary<string, string, string>(i => i.Split('=')[0], i => i.Split('=').Length > 1 ? i.Split('=')[1] : null);
                string antiForgeryCookie = setCookieDictionary.First().Value;
                Stream dataStream = response.GetResponseStream();
                StreamReader reader = new StreamReader(dataStream);
                string responseFromServer = reader.ReadToEnd();
                HtmlDocument doc = new HtmlDocument();
                doc.LoadHtml(responseFromServer);
                HtmlNode requestVerificationTokenNode = doc.DocumentNode.Descendants().Where(node => node.GetAttributeValue("name", "Error") == RequestVerificationToken).First();
                string token = requestVerificationTokenNode.GetAttributeValue("value", "Error");
                
                RequestTelemetry requestTelemetry = new RequestTelemetry();
                requestTelemetry.Url = new Uri(loginUrl);
                requestTelemetry.ResponseCode = response.StatusCode.ToString();
                requestTelemetry.Name = "Get Token";
                requestTelemetry.Properties.Add("AntiForgeryCookie", antiForgeryCookie);
                telemetryClient.TrackRequest(requestTelemetry);
                telemetryClient.Flush();

                // sign in
                request = WebRequest.CreateHttp(loginUrl);
                request.Method = "Post";
                request.ContentType = "application/x-www-form-urlencoded";
                Uri target = new Uri(loginUrl);
                CookieContainer cookieContainer = new CookieContainer();
                cookieContainer.Add(new Cookie(RequestVerificationToken, antiForgeryCookie) { Domain = target.Host });
                request.CookieContainer = cookieContainer;
                Stream signInStream = request.GetRequestStream();
                Dictionary<string, string> signInContentDictionary = new Dictionary<string, string>();
                signInContentDictionary.Add(RequestVerificationToken, token);
                signInContentDictionary.Add("ComputerTypes", "PublicComputer");
                signInContentDictionary.Add("UserName", RoleEnvironment.GetConfigurationSettingValue("username"));
                signInContentDictionary.Add("Password", RoleEnvironment.GetConfigurationSettingValue("password"));
                string signInContentDictionaryString = string.Join("&", signInContentDictionary.Select(x => x.Key + "=" + x.Value).ToArray());
                byte[] signInContentBytes = Encoding.ASCII.GetBytes(signInContentDictionaryString);
                signInStream.Write(signInContentBytes, 0, signInContentBytes.Length);
                signInStream.Close();
                response = (HttpWebResponse)request.GetResponse();

                requestTelemetry = new RequestTelemetry();
                requestTelemetry.Url = new Uri(loginUrl);
                requestTelemetry.ResponseCode = response.StatusCode.ToString();
                requestTelemetry.Name = "Login";
                requestTelemetry.Properties.Add("RequestVerificationToken", token);
                telemetryClient.TrackRequest(requestTelemetry);
                telemetryClient.Flush();

                // Book
                request = WebRequest.CreateHttp(bookUrl);
                request.Method = "Post";
                request.ContentType = "application/x-www-form-urlencoded; charset=UTF-8";
                request.CookieContainer = cookieContainer;
                Stream bookingStream = request.GetRequestStream();
                Dictionary<string, string> bookingDictionary = new Dictionary<string, string>();
                bookingDictionary.Add("AMorPMValue", "PM");
                bookingDictionary.Add("NeedsBikeRack", "false");
                bookingDictionary.Add("DatePicker", HttpUtility.UrlEncode(DateTime.Today.AddDays(1).ToShortDateString()));
                bookingDictionary.Add("DropDownList", "10324");
                bookingDictionary.Add("DropDownListPick", "1");
                bookingDictionary.Add("DropDownListDrop", "63");
                bookingDictionary.Add("rbScheds", "118");
                bookingDictionary.Add("IsFavorite", "false");
                bookingDictionary.Add("X-Requested-With", "XMLHttpRequest");
                string bookingDictionaryString = string.Join("&", bookingDictionary.Select(x => x.Key + "=" + x.Value).ToArray());
                byte[] bookingDictionaryBytes = Encoding.ASCII.GetBytes(bookingDictionaryString);
                bookingStream.Write(bookingDictionaryBytes, 0, bookingDictionaryBytes.Length);
                bookingStream.Close();
                await Task.Delay(10000);
                response = (HttpWebResponse)request.GetResponse();

                requestTelemetry = new RequestTelemetry();
                requestTelemetry.Url = new Uri(bookUrl);
                requestTelemetry.ResponseCode = response.StatusCode.ToString();
                requestTelemetry.Name = "Book";
                requestTelemetry.Properties.Concat(bookingDictionary);
                telemetryClient.TrackRequest(requestTelemetry);
                telemetryClient.Flush();


                await Task.Delay(60*1000*24);
            }
        }
    }
}
