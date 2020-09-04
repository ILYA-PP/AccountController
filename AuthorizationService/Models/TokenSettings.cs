using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.ConstrainedExecution;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace AuthorizationService.Models
{
    public class TokenSettings
    {
        public string Issuer { get; set; }
        public string Audience { get; set; }
        public int AuthLifetime { get; set; }
        public CertificateSettings Certificate { get; set; }

        private X509Certificate2 _certificate;

        internal SecurityKey GetSecurityKey()
        {
            var certificate = GetCertificate();

            return new X509SecurityKey(certificate);
        }

        internal X509Certificate2 GetCertificate()
        {
            if(Certificate == null)
                throw new InvalidOperationException("JWT Certificate not configured");

            if (_certificate == null)
            {
                try
                {
                    _certificate = new X509Certificate2(Certificate.Path, Certificate.Password);
                }
                catch(Exception ex)
                {
                    throw new InvalidOperationException("JWT Certificate configuration not valid", ex);
                }
            }

            return _certificate;
        }
    }
}
