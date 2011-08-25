using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace pkild.net
{
    public class ResponseParser
    {
        private static readonly Regex CreateCertificateFlag =
            new Regex("<div id=\"option_create_pkcs12\">", RegexOptions.Compiled);

        private static readonly Regex CertificateExistsRegex =
            new Regex("<legend>(.+)</legend>", RegexOptions.Compiled);

        private static readonly Regex MainPageRegex =
            new Regex("<body onload=\"styleResize", RegexOptions.Compiled);

        private static readonly Regex RevocationNode =
            new Regex("<input type=\"hidden\" name=\"node_name\" value=\"(.+)\"", RegexOptions.Compiled);

        private const string RemoveCertificateValue = "Remove Certificate";
        private const string RevokeCertificateValue = "Revoke Certificate";

        public String RevocationNodeName { get; protected set; }
        public CertificateState CertificateState { get; protected set; }

        public ResponseParser(String html)
        {
            if (CreateCertificateFlag.IsMatch(html))
            {
                CertificateState = CertificateState.Missing;
                return;
            }

            if (MainPageRegex.IsMatch(html))
            {
                CertificateState = CertificateState.Unknown;
                return;
            }

            Match regexMatch = CertificateExistsRegex.Match(html);
            if (!regexMatch.Success)
            {
                throw new Exception(String.Format("Unknown response from pkild server: {0}", html));
            }

            if (regexMatch.Groups.Count != 2)
            {
                throw new Exception(
                    String.Format("Incorrect number of matching groups in regex search: Expected 2, got {0}", regexMatch.Groups.Count)
                    );
            }

            String stateString = regexMatch.Groups[1].ToString();
            switch (stateString)
            {
                case RemoveCertificateValue:
                    CertificateState = CertificateState.Revoked;
                    break;
                case RevokeCertificateValue:
                    CertificateState = CertificateState.Present;
                    break;
                default:
                    throw new Exception("Unknown certificate state value: " + stateString);
            }
            GetRevocationNode(html);
        }

        private void GetRevocationNode(string html)
        {
            var match = RevocationNode.Match(html);
            if (match.Groups.Count != 2)
                throw new Exception("Can't find revocation node name");
            RevocationNodeName = match.Groups[1].ToString();
        }
    }
}
