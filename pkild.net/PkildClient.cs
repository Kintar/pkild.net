using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net;
using System.IO;
using System.Web;
using System.Runtime.InteropServices;

namespace pkild.net
{
    public class PkildClient : IPkiClient
    {
        public Uri BaseUri { get; protected set; }
        public CertificateState CertificateState { get; protected set; }
        public PkildSession Session { get; protected set; }
        public bool IsLoggedIn { get; protected set; }
        private String certRevokeNode;

        public PkildClient(Uri baseUri)
        {
            BaseUri = baseUri;
            CertificateState = CertificateState.Unknown;
            Initialize();
        }

        private void Initialize()
        {
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(BaseUri);
            using (WebResponse resp = request.GetResponse())
            {
                String cookies = resp.Headers[HttpResponseHeader.SetCookie];

                if (cookies.ToString().StartsWith("pkild_session"))
                    Session = new PkildSession(cookies.ToString());
            }
        }

        public PkildClient(String baseUri) : this(new Uri(baseUri)) { }

        public void Login(String user, String password)
        {
            Session = Login_Internal(user, password);
            IsLoggedIn = true;
            FetchCertificateState();
        }

        public void Logout()
        {
            Session = null;
            IsLoggedIn = false;
        }

        public byte[] CreateCertificate(String password)
        {
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(BaseUri);

            String parameters = String.Format("password={0}&confirm_password={0}&submit=create&action_type=pkcs12_cert",
                HttpUtility.UrlEncode(password));

            request.Method = "POST";
            request.ContentType = "application/x-www-form-urlencoded";
            request.Headers[HttpRequestHeader.Cookie] = "pkild_session=" + Session.SessionID;
            using (Stream reqStream = request.GetRequestStream())
            using (StreamWriter writer = new StreamWriter(reqStream))
            {
                writer.Write(parameters);
            }
            using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
            {
                if (response.StatusCode != HttpStatusCode.OK)
                    throw new Exception("Bad response code: " + response.StatusCode);

                if (response.ContentType != "application/x-pkcs12")
                    return FetchCertificate();

                using (Stream responseStream = response.GetResponseStream())
                {
                    byte[] certBytes = new byte[response.ContentLength];
                    responseStream.Read(certBytes, 0, certBytes.Length);
                    CertificateState = CertificateState.Present;
                    return certBytes;
                }
            }
        }

        private byte[] FetchCertificate()
        {
            HttpWebRequest req = (HttpWebRequest)WebRequest.Create(BaseUri);
            req.Method = "GET";
            req.Headers[HttpRequestHeader.Cookie] = "pkild_session=" + Session.SessionID;
            using (HttpWebResponse response = (HttpWebResponse)req.GetResponse())
            {
                if (response.ContentType != "application/x-pkcs12")
                    throw new Exception("Could not fetch certificate");

                using (Stream responseStream = response.GetResponseStream())
                {
                    byte[] certBytes = new byte[response.ContentLength];
                    responseStream.Read(certBytes, 0, certBytes.Length);
                    CertificateState = CertificateState.Present;
                    return certBytes;
                }
            }
        }

        public bool RevokeCertificate()
        {
            if (CertificateState != CertificateState.Present)
                throw new Exception("Can't revoke a missinr or already revoked certificate");

            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(BaseUri);
            request.Method = "POST";

            String requestData = "revoke_cert=revoke&action_type=revoke_cert&node_name=" + certRevokeNode;
            request.ContentType = "application/x-www-form-urlencoded";
            request.Headers[HttpRequestHeader.Cookie] = "pkild_session=" + Session.SessionID;
            using (Stream reqStream = request.GetRequestStream())
            using (StreamWriter writer = new StreamWriter(reqStream))
            {
                writer.Write(requestData);
            }

            using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
            {
                if (response.StatusCode != HttpStatusCode.OK)
                    throw new Exception("Failed to revoke certificate: Server returned status code " + response.StatusCode.ToString());

                using (Stream responseStream = response.GetResponseStream())
                {
                    var parser = new ResponseParser(new StreamReader(responseStream).ReadToEnd());
                    certRevokeNode = parser.RevocationNodeName;
                }
            }

            FetchCertificateState();
            return CertificateState == CertificateState.Revoked;
        }

        public bool RemoveCertificate()
        {
            if (CertificateState != CertificateState.Revoked)
                throw new Exception("Can't remove a non-revoked certificate");

            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(BaseUri);
            request.Method = "POST";

            String requestData = "remove_cert=remove&action_type=remove_cert&node_name=" + certRevokeNode;
            request.ContentType = "application/x-www-form-urlencoded";
            request.Headers[HttpRequestHeader.Cookie] = "pkild_session=" + Session.SessionID;
            using (Stream reqStream = request.GetRequestStream())
            using (StreamWriter writer = new StreamWriter(reqStream))
            {
                writer.Write(requestData);
            }
            using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
            {
                if (response.StatusCode != HttpStatusCode.OK)
                    throw new Exception("Failed to remove certificate: Server returned status code " + response.StatusCode.ToString());
            }

            certRevokeNode = null;
            FetchCertificateState();
            return CertificateState == CertificateState.Missing;
        }

        /// <summary>
        /// Logs in and returns the session ID
        /// </summary>
        /// <param name="user"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        private PkildSession Login_Internal(String user, String password)
        {
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(BaseUri);
            request.Method = "POST";

            String requestData = String.Format(
                "username={0}&password={1}&login=Submit", HttpUtility.UrlEncode(user, Encoding.UTF8), HttpUtility.UrlEncode(password));
            request.ContentType = "application/x-www-form-urlencoded";
            request.Headers[HttpRequestHeader.Cookie] = "pkild_session=" + Session.SessionID;
            using (Stream reqStream = request.GetRequestStream())
            using (StreamWriter writer = new StreamWriter(reqStream))
            {
                writer.Write(requestData);
            }
            using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
            {
                if (response.StatusCode != HttpStatusCode.OK)
                    throw new Exception("Failed to log in: Server returned status code " + response.StatusCode.ToString());

                String cookies = response.Headers[HttpResponseHeader.SetCookie];

                using (Stream responseStream = response.GetResponseStream())
                {
                    var parser = new ResponseParser(new StreamReader(responseStream).ReadToEnd());
                    certRevokeNode = parser.RevocationNodeName;
                    CertificateState = parser.CertificateState;
                }
                
                if (cookies.ToString().StartsWith("pkild_session"))
                    return new PkildSession(cookies.ToString());

                throw new Exception("Unexpected response from server");
            }
        }

        private void FetchCertificateState()
        {
            CertificateState = net.CertificateState.Unknown;
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(new Uri(BaseUri.ToString() + "/action/select/6e65775f63657274"));
            request.Method = "POST";
            request.Headers[HttpRequestHeader.Cookie] = "pkild_session=" + Session.SessionID;
            request.Headers["X-Requested-With"] = "XMLHttpRequest";
            using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
            {
                if (response.StatusCode != HttpStatusCode.OK)
                    throw new Exception("Unexpected status code: " + response.StatusCode);

                using (Stream respStream = response.GetResponseStream())
                using (StreamReader reader = new StreamReader(respStream))
                {
                    var parser = new ResponseParser(reader.ReadToEnd());
                    CertificateState = parser.CertificateState;
                    certRevokeNode = parser.RevocationNodeName;
                }
            }
        }

    }
}
