using System;
using System.Threading;

namespace Firewall
{
    internal sealed class RemoveCommentsInspector : IResponseInspector
    {
        public void Inspect(ResponseAnalysisContext context, CancellationToken cancellationToken)
        {
            if (context.IsHtml())
            {
                var body = context.ReadAsString();
                if (body != null)
                {
                    foreach (var comment in FastHtmlParser.FindAllComments(body))
                    {
                        if (
                            // respect Knockout.js comments
                            comment.StartsWith("<!-- ko", StringComparison.Ordinal) ||
                            comment.StartsWith("<!-- /ko", StringComparison.Ordinal) ||

                            // respect IE conditional comments
                            comment.StartsWith("<!--[if ", StringComparison.Ordinal) ||
                            comment.StartsWith("[endif]-->", StringComparison.Ordinal)
                        )
                        {
                            continue;
                        }

                        context.AddChange(TextChange.Remove(body, comment.Offset, comment.Length));
                    }
                }
            }
        }
    }
}
