using Microsoft.IdentityModel.Clients.ActiveDirectory;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace WorkerRole1
{
    class KeyVaultAuthHelper
    {
        private static ClientAssertionCertificate AssertionCert;

        // Used for Certs
        public static async Task<string> GetAccessToken(string authority, string resource, string scope)
        {
            AssertionCert = CertHelper.GetCert();

            // https://docs.microsoft.com/en-us/azure/key-vault/key-vault-use-from-web-application#authenticate-with-a-certificate-instead-of-a-client-secret
            var context = new AuthenticationContext(authority, TokenCache.DefaultShared);
            var result = await context.AcquireTokenAsync(resource, AssertionCert);
            return result.AccessToken;
        }

        // Used for keys
        public async Task<string> GetAccessToken2(string authority, string resource, string scope)
        {
            throw new NotImplementedException();

            // http://www.rahulpnath.com/blog/authenticating-a-client-application-with-azure-key-vault/
            var clientCred = new ClientCredential("_client_id_", "_active_directory_key_"); // this is a secret. the solution is to use a certificate.
            var authContext = new AuthenticationContext(authority);
            var result = await authContext.AcquireTokenAsync(resource, clientCred);
            return result.AccessToken;
        }
    }
}
