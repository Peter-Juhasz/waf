using Microsoft.AspNetCore.Antiforgery;
using System;
using System.Text.Encodings.Web;
using System.Threading;
using System.Threading.Tasks;

namespace Firewall
{
    public class AntiforgeryResponseInspector : IAsyncRequestInspector, IResponseInspector
    {
        public AntiforgeryResponseInspector(IAntiforgery antiforgery)
        {
            Antiforgery = antiforgery;
        }

        public IAntiforgery Antiforgery { get; }

        private static readonly Rule Rule = new Rule("1", WellKnownCategories.InformationDisclosure, "Information leakage.");

        public async Task InspectAsync(RequestAnalysisContext context, CancellationToken cancellationToken)
        {
            if (context.Request.Method.Equals("post", StringComparison.OrdinalIgnoreCase) && context.Request.HasFormContentType)
            {
                bool valid = await Antiforgery.IsRequestValidAsync(context.HttpContext);
                if (!valid)
                {
                    context.ReportDiagnostic(new Diagnostic(Rule, Location.RequestBody));
                }
            }
        }

        public void Inspect(ResponseAnalysisContext context, CancellationToken cancellationToken)
        {
            if (context.IsHtml())
            {
                // read content
                string html = context.ReadAsString();
                if (html == null)
                {
                    return;
                }

                string csrfTag = null;

                // enumerate forms
                foreach (var formIndex in FastHtmlParser.FindAllTagIndexes(html, "form"))
                {
                    // check method attribute
                    var method = FastHtmlParser.GetAttributeValueAtTag(html, "method", formIndex);
                    if (method.Equals("post", StringComparison.OrdinalIgnoreCase))
                    {
                        // generate CSRF hidden field
                        if (csrfTag == null)
                        {
                            var tokens = Antiforgery.GetAndStoreTokens(context.HttpContext);
                            csrfTag = $"<input type=\"hidden\" name=\"{HtmlEncoder.Default.Encode(tokens.FormFieldName)}\" value=\"{HtmlEncoder.Default.Encode(tokens.RequestToken)}\" />";
                        }

                        // insert field
                        int close = FastHtmlParser.FindClosePairFlatIndex(html, "form", formIndex);
                        context.AddChange(TextChange.Insert(html, close, csrfTag));
                    }
                }
            }
        }
    }
}
