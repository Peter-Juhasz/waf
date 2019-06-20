using Microsoft.Extensions.Primitives;
using System;
using System.Linq;
using System.Threading;

namespace Firewall
{
    public class UpgradeCookieResponseInspector :  IResponseInspector
    {
        public void Inspect(ResponseAnalysisContext context, CancellationToken cancellationToken)
        {
            if (context.Response.Headers.TryGetValue("Set-Cookie", out var values))
            {
                if (values.Any(v => !IsSecure(v)))
                {
                    context.Response.Headers["Set-Cookie"] = new StringValues(values.Select(MakeSecure).ToArray());
                }
            }
        }

        private static bool IsSecure(string v) => new StringTokenizer(v, new[] { ';' }).Any(v => v.Trim().Equals("Secure", StringComparison.OrdinalIgnoreCase));

        private static string MakeSecure(string arg) => IsSecure(arg) ? arg : arg + "; Secure";
    }
}
