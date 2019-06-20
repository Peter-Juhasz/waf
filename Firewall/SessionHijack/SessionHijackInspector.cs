using Microsoft.Extensions.Primitives;
using System;
using System.Threading;

namespace Firewall
{
    public class SessionHijackInspector : IResponseInspector
    {
        private const int MinimumCookieLength = 16;

        private static readonly Rule Rule = new Rule("2", WellKnownCategories.Hijack, "Session hijack.");

        public void Inspect(ResponseAnalysisContext context, CancellationToken cancellationToken)
        {
            if (context.Response.Headers.TryGetValue("Set-Cookie", out var setCookies))
            {
                // inspect cookies
                foreach (var setCookie in setCookies)
                {
                    // parse name
                    int delimiterIndex = setCookie.IndexOf('=');
                    var name = new StringSegment(setCookie, 0, delimiterIndex);

                    if (!name.Contains("sess", StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    // parse value
                    int semicolonIndex = setCookie.IndexOf(';', delimiterIndex + 1);
                    var value = new StringSegment(setCookie, delimiterIndex + 1, semicolonIndex != -1 ? semicolonIndex : (setCookie.Length - delimiterIndex - 1));
                    if (value.Length < MinimumCookieLength)
                    {
                        continue;
                    }

                    // match to query string
                    foreach (var query in context.HttpContext.Request.Query)
                    foreach (var queryValue in query.Value)
                    {
                        if (value.Contains(queryValue))
                        {
                            context.ReportDiagnostic(new Diagnostic(Rule, Location.QueryString(query.Key)));
                            return;
                        }
                    }
                }
            }
        }
    }
}
