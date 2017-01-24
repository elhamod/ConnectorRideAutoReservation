using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Microsoft.WindowsAzure.ServiceRuntime;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace WorkerRole1
{
    class CertHelper
    {
        private static X509Certificate2 FindCertificateByThumbprint(string findValue)
        {
            X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            try
            {
                store.Open(OpenFlags.ReadOnly);
                X509Certificate2Collection col = store.Certificates.Find(X509FindType.FindByThumbprint,
                    findValue, false); // Don't validate certs, since the test root isn't installed.
                if (col == null || col.Count == 0)
                    return null;
                return col[0];
            }
            finally
            {
                store.Close();
            }
        }

        public static ClientAssertionCertificate GetCert()
        {
            var clientAssertionCertPfx = FindCertificateByThumbprint(RoleEnvironment.GetConfigurationSettingValue("certThumbprint"));
            return new ClientAssertionCertificate(RoleEnvironment.GetConfigurationSettingValue("clientId"), clientAssertionCertPfx);
        }

    }
}
