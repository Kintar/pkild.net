using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace pkild.net
{
    public interface IPkiClient
    {
        byte[] CreateCertificate(String password);

        bool RevokeCertificate();

        bool RemoveCertificate();
    }
}
