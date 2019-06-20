using Microsoft.AspNetCore.Http;
using System;
using System.Threading;

namespace Firewall
{
    internal sealed class RemoveGeneratorInspector : IResponseInspector
    {
        public void Inspect(ResponseAnalysisContext context, CancellationToken cancellationToken)
        {
            if (context.IsHtml())
            {
                InspectBody(context);
            }
        }

        private static void InspectBody(ResponseAnalysisContext context)
        {
            var html = context.ReadAsString();
            if (html != null)
            {
                foreach (var index in FastHtmlParser.FindAllTagIndexes(html, "meta"))
                {
                    if (FastHtmlParser.GetAttributeValueAtTag(html, "name", index).Equals("generator", StringComparison.OrdinalIgnoreCase))
                    {
                        var end = FastHtmlParser.FindEndOfOpenTag(html, index) + 1;
                        context.AddChange(TextChange.Remove(html, index, end - index));
                    }
                }
            }
        }
    }
}
