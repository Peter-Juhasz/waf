using Microsoft.AspNetCore.Http;
using System;
using System.Linq;
using System.Threading;

namespace Firewall
{
    public class RewriteHttpsInspector : IResponseInspector
    {
        public void Inspect(ResponseAnalysisContext context, CancellationToken cancellationToken)
        {
            InspectHeader(context.Response);

            if (context.IsHtmlOrCssOrJs())
            {
                InspectBody(context);
            }
        }

        private static void InspectBody(ResponseAnalysisContext context)
        {
            string body = context.ReadAsString();
            if (body != null)
            {
                // rewrite HTML
                if (context.IsHtml())
                {
                    foreach (var index in body.AllIndexesOf("http:", StringComparison.OrdinalIgnoreCase))
                    {
                        // make sure it is inside an attribute
                        var attributeName = FastHtmlParser.GetAttributeNameFromValueIndex(body, index);
                        if (attributeName.Equals("src", StringComparison.OrdinalIgnoreCase) ||
                            attributeName.Equals("href", StringComparison.OrdinalIgnoreCase) ||
                            attributeName.Equals("srcset", StringComparison.OrdinalIgnoreCase))
                        {
                            context.AddChange(TextChange.Insert(body, index + "http".Length, "s"));

                            // 'xmlns' excluded
                        }
                    }
                }

                // rewrite CSS
                if (context.IsCss())
                {
                    foreach (var index in body.AllIndexesOf("http:", StringComparison.OrdinalIgnoreCase))
                    {
                        context.AddChange(TextChange.Insert(body, index + "http".Length, "s"));
                    }
                }
            }
        }

        private static void InspectHeader(HttpResponse response)
        {
            if (response.Headers.TryGetValue("Location", out var values))
            {
                if (values.Any(v => v.StartsWith("http:", StringComparison.OrdinalIgnoreCase)))
                {
                    response.Headers["Location"] = values.Select(v => v.Replace("http:", "https:", StringComparison.OrdinalIgnoreCase)).ToArray();
                }
            }
        }
    }
}
