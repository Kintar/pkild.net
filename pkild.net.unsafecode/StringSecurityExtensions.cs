using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security;
using System.Runtime.InteropServices;
using System.IO;

namespace pkild.net.unsafecode
{
    public static class StringSecurityExtensions
    {
        /// <summary>
        /// Replaces the contents of this managed String with an equal-length sequence of nulls
        /// </summary>
        /// <param name="str"></param>
        public unsafe static void Zero(this String str)
        {
            fixed (char* chars = str)
            {
                for (int i = 0; i < str.Length; i++)
                {
                    chars[i] = '\0';
                }
            }
        }

        /// <summary>
        /// Converts the string to a SecureString, then replaces the contents of this managed string
        /// with an equal-length sequence of nulls.
        /// </summary>
        /// <remarks>
        /// <b>IMPORTANT:</b> If you're using this method in test code that has hard-coded string values (yes, it's
        /// bad, but very expedient at times), remember that the compiler is optimization-crazy.  All instances of
        /// the value you're converting and zeroing will be zeroed, even other string literals of the same value,
        /// and even string literals made up of concatenated strings that result in the same literal value.
        /// 
        /// I.e.,  "testpassword".ConvertToSecureStringAndZero() will mean that all instances of "testpassword" in 
        /// your code have been zeroed, as will "test" + "password" and the like.
        /// </remarks>
        /// <param name="str"></param>
        /// <returns></returns>
        public unsafe static SecureString ConvertToSecureStringAndZero(this String str)
        {
            SecureString secure = new SecureString();
            fixed (char* chars = str)
            {
                for (int i = 0; i < str.Length; i++)
                {
                    secure.AppendChar(chars[i]);
                    chars[i] = '\0';
                }
            }
            secure.MakeReadOnly();
            return secure;
        }

        /// <summary>
        /// Converts a SecureString to a managed string.  REMEMBER: When you're done with the string,
        /// call String.Zero()
        /// </summary>
        /// <param name="secure"></param>
        /// <returns></returns>
        public static String ConvertToUnsecureString(this SecureString secure)
        {
            IntPtr securePointer = Marshal.SecureStringToGlobalAllocUnicode(secure);
            String result = Marshal.PtrToStringUni(securePointer);
            Marshal.ZeroFreeGlobalAllocUnicode(securePointer);
            return result;
        }

        /// <summary>
        /// Writes the contents of a SecureString to the given stream, using the passed Encoding to convert
        /// the string to bytes
        /// </summary>
        /// <param name="secure"></param>
        /// <param name="stream"></param>
        /// <param name="encoding"></param>
        public unsafe static void WriteToStream(this SecureString secure, Stream stream, Encoding encoding)
        {
            IntPtr securePointer = Marshal.SecureStringToGlobalAllocUnicode(secure);
            String unsecure = null;
            try
            {
                unsecure = Marshal.PtrToStringUni(securePointer);
                int byteLen = encoding.GetByteCount(unsecure);
                fixed (byte* bytes = encoding.GetBytes(unsecure))
                {
                    for (int b = 0; b < byteLen; b++)
                    {
                        stream.WriteByte(bytes[b]);
                    }
                }
            }
            finally
            {
                Marshal.ZeroFreeGlobalAllocUnicode(securePointer);
                if (unsecure != null)
                    unsecure.Zero();
            }
        }

        /// <summary>
        /// Writes the contents of a SecureString to the given stream, using Encoding.UTF8 to
        /// convert the string to bytes.
        /// </summary>
        /// <param name="secure"></param>
        /// <param name="stream"></param>
        public static void WriteToStream(this SecureString secure, Stream stream)
        {
            secure.WriteToStream(stream, Encoding.UTF8);
        }
    }

}
