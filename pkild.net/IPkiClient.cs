using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security;

namespace pkild.net
{
    public interface IPkiClient
    {
        CertificateState CertificateState { get; }

        bool IsLoggedIn { get; }

        byte[] CreateCertificate(SecureString password);

        bool RevokeCertificate();

        bool RemoveCertificate();

        void Login(String user, SecureString password);

        void Logout();
    }
}
