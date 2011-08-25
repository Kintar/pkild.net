using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace pkild.net
{
    public class PkildSession
    {
        private const string DateFormat = "ddd, dd-MMM-yyyy HH:mm:ss 'GMT'";
        public String SessionID { get; protected set; }
        public DateTime ExpirationDate { get; protected set; }
        public bool IsExpired
        {
            get
            {
                return DateTime.Now.CompareTo(ExpirationDate) > 0;
            }
        }

        public PkildSession(String cookieSyntax)
        {
            ExpirationDate = DateTime.MinValue;

            String[] values = cookieSyntax.Split(';');
            foreach (var value in values)
            {
                String[] keyval = value.Split('=');
                switch (keyval[0].Trim())
                {
                    case "pkild_session":
                        SessionID = keyval[1].Trim();
                        break;
                    case "expires":
                        ExpirationDate = DateTime.ParseExact(keyval[1].Trim(), DateFormat, null);
                        break;
                }
            }

            if (SessionID == null) throw new Exception("No pkild_session found in cookie");
            if (ExpirationDate == DateTime.MinValue) throw new Exception("No expiration time found in cookie");
        }
    }
}
