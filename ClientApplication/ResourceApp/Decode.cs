using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace ResourceApp
{
    public static class Decode
    {
        public static byte[] DecodeUrlBase64(string s)
        {
            s = s.Replace('-', '+').Replace('_', '/').PadRight(4 * ((s.Length + 3) / 4), '=');
            return Convert.FromBase64String(s);
        }

    }
}
