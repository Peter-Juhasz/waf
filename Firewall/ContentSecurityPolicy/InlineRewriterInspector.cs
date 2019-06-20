using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.ObjectPool;
using Microsoft.Extensions.Primitives;
using System;
using System.Buffers;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Text;
using System.Threading;

namespace Firewall.ContentSecurityPolicy
{
    public class InlineRewriterInspector : IResponseInspector
    {
        public InlineRewriterInspector(
            IMemoryCache memoryCache,
            InlineContentService inlineContentService,
            ObjectPool<StringBuilder> stringBuilderPool
        )
        {
            MemoryCache = memoryCache;
            InlineContentService = inlineContentService;
            StringBuilderPool = stringBuilderPool;
        }

        public IMemoryCache MemoryCache { get; }
        public InlineContentService InlineContentService { get; }
        public ObjectPool<StringBuilder> StringBuilderPool { get; }

        private ConcurrentDictionary<string, InlineContent> ContentHashCache = new ConcurrentDictionary<string, InlineContent>();

        private const int HashBytes = 256 / 8;

        public void Inspect(ResponseAnalysisContext context, CancellationToken cancellationToken)
        {
            if (context.IsHtml())
            {
                string html = context.ReadAsString();
                if (html == null)
                {
                    return;
                }

                RewriteStyleTags(context, html);
                RewriteScriptTags(context, html);
                RewriteStyleAttributes(context, html);
            }
        }

        private void RewriteStyleAttributes(ResponseAnalysisContext context, string html)
        {
            var headIndex = html.IndexOf("</head>", StringComparison.OrdinalIgnoreCase);
            if (headIndex == -1)
            {
                return;
            }

            SortedList<string, StringSegment> inlineStyles = null;
            foreach (var index in FastHtmlParser.FindAllAttributeIndexes(html, "style"))
            {
                // get content
                var inner = FastHtmlParser.GetAttributeValueAtName(html, "style", index);
                if (inner.Length == 0)
                {
                    continue;
                }

                if (inlineStyles == null)
                {
                    inlineStyles = new SortedList<string, StringSegment>();
                }

                // compute hash
                var hash = ComputeHash(inner.Trim());

                if (!inlineStyles.ContainsKey(hash))
                {
                    inlineStyles.Add(hash, inner);
                }

                // add change
                context.AddChange(TextChange.Remove(html, index, inner.Offset + inner.Length + 1 - index));

                var tagIndex = FastHtmlParser.FindOpenTagAtAttribute(html, index);
                var classAttribute = FastHtmlParser.GetAttributeValueAtTag(html, "class", tagIndex);
                if (classAttribute.Length > 0)
                {
                    context.AddChange(TextChange.Insert(html, classAttribute.Offset + classAttribute.Length, "_" + hash));
                }
                else
                {
                    context.AddChange(FastHtmlParser.CreateInsertAttributeChange(html, tagIndex, "class", "_" + hash));
                }
            }

            // assemble inline styles
            if (inlineStyles != null && inlineStyles.Count > 0)
            {
                var hashBuilder = new InplaceStringBuilder(inlineStyles.Count * HashBytes * 2);
                foreach (var entry in inlineStyles)
                {
                    hashBuilder.Append(entry.Key);
                }

                var hash = ComputeHash(hashBuilder.ToString());
                if (!InlineContentService.ContainsStyleByHash(hash))
                {
                    var contentBuilder = StringBuilderPool.Get();
                    foreach (var entry in inlineStyles)
                    {
                        contentBuilder.Append('.');
                        contentBuilder.Append('_');
                        contentBuilder.Append(entry.Key);
                        contentBuilder.Append('{');
                        contentBuilder.Append(entry.Value.Value);
                        contentBuilder.Append('}');
                    }
                    InlineContentService.TryAddStyleByHash(hash, contentBuilder.ToString());
                    StringBuilderPool.Return(contentBuilder);
                }

                var tag = $"<link rel=\"stylesheet\" href=\"/.waf/styles/{hash}\" type=\"text/css\" />";
                context.AddChange(TextChange.Insert(html, headIndex, tag));
            }
        }

        private void RewriteScriptTags(ResponseAnalysisContext context, string html)
        {
            foreach (var index in FastHtmlParser.FindAllTagIndexes(html, "script"))
            {
                var type = FastHtmlParser.GetAttributeValueAtTag(html, "type", index);
                if (!type.Equals("text/javascript", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                // get content
                var inner = FastHtmlParser.GetInnerHtml(html, index, "script");
                if (inner == null || inner.Value.Trim().Length == 0)
                {
                    continue;
                }

                // compute hash
                var inline = ContentHashCache.GetOrAdd(inner.Value.Trim().TrimHtmlCdata().Trim().Value, v => CreateContent(v));
                InlineContentService.TryAddScriptByHash(inline.Hash, inline.Content);

                // add change
                context.AddChange(TextChange.Remove(html, inner.Value.Offset, inner.Value.Length));
                context.AddChange(FastHtmlParser.CreateInsertAttributeChange(html, index, "script", "src", $"/.waf/scripts/{inline.Hash}"));
            }
        }

        private void RewriteStyleTags(ResponseAnalysisContext context, string html)
        {
            foreach (var index in FastHtmlParser.FindAllTagIndexes(html, "style"))
            {
                // get content
                var inner = FastHtmlParser.GetInnerHtml(html, index, "style");
                if (inner == null)
                {
                    continue;
                }

                // compute hash
                var inline = ContentHashCache.GetOrAdd(inner.Value.Trim().TrimHtmlCdata().Trim().Value, v => CreateContent(v));
                InlineContentService.TryAddStyleByHash(inline.Hash, inline.Content);

                // add change
                var tagSpan = FastHtmlParser.GetFullTagSpan(html, index, "style");
                context.AddChange(TextChange.Replace(html, index, tagSpan.Value.Length, inline.Tag));
            }
        }

        private string ComputeHash(StringSegment style)
        {
            var size = Encoding.UTF8.GetByteCount(style);
            var buffer = ArrayPool<byte>.Shared.Rent(size);
            Encoding.UTF8.GetBytes(style, buffer);

            var hash = ArrayPool<byte>.Shared.Rent(32);
            HashAlgorithmPool.Sha256.TryComputeHash(buffer.AsSpan(0, size), hash, out var _);
            ArrayPool<byte>.Shared.Return(buffer);

            var str = hash.AsSpan(0, HashBytes).ToHexString();
            ArrayPool<byte>.Shared.Return(hash);
            return str;
        }

        private InlineContent CreateContent(StringSegment style)
        {
            string hash = ComputeHash(style);
            var uri = $"/.waf/styles/{hash}";
            var linkTag = $"<link rel=\"stylesheet\" type=\"text/css\" href=\"{uri}\" />";
            return new InlineContent
            {
                Content = style.Value,
                Hash = hash,
                Tag = linkTag,
            };
        }


        private class InlineContent
        {
            public string Content { get; set; }

            public string Tag { get; set; }

            public string Hash { get; set; }
        }
    }
}
