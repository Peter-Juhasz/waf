using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Primitives;
using System;
using System.Linq;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace Firewall
{
    internal class SubResourceIntegrityInspector : IAsyncResponseInspector
    {
        public SubResourceIntegrityInspector(IHttpClientFactory httpClientFactory, IMemoryCache memoryCache)
        {
            HttpClientFactory = httpClientFactory;
            MemoryCache = memoryCache;
        }

        public IHttpClientFactory HttpClientFactory { get; }
        public IMemoryCache MemoryCache { get; }

        public async Task InspectAsync(ResponseAnalysisContext context, CancellationToken cancellationToken)
        {
            if (context.IsHtml())
            {
                var html = context.ReadAsString();

                // find all script tags
                foreach (var index in FastHtmlParser.FindAllTagIndexes(html, "script"))
                {
                    // get 'src' attribute
                    var src = FastHtmlParser.GetAttributeValueAtTag(html, "src", index);
                    if (src.IndexOf(':') != -1 || src.StartsWith("//", StringComparison.Ordinal))
                    {
                        // check whether there is an 'integrity' attribute alrady
                        var integrity = FastHtmlParser.GetAttributeValueAtTag(html, "integrity", index);
                        if (integrity.Length > 0)
                        {
                            continue;
                        }

                        // compute integrity
                        var sri = await MemoryCache.GetOrCreateAsync($"SRI_{src}", async ce =>
                        {
                            ce.SetAbsoluteExpiration(DateTimeOffset.MaxValue);
                            ce.SetPriority(CacheItemPriority.High);

                            var client = HttpClientFactory.CreateClient();
                            try
                            {
                                // download script
                                using var request = new HttpRequestMessage(HttpMethod.Get, RelativeTo(src).ToString());
                                request.Headers.TryAddWithoutValidation("Origin", $"{context.HttpContext.Request.Scheme}://{context.HttpContext.Request.Host}");
                                using var response = await client.SendAsync(request);
                                if (!response.IsSuccessStatusCode)
                                {
                                    return null;
                                }

                                if (response.Content == null)
                                {
                                    return null;
                                }

                                if (!response.Headers.Any(h => h.Key.StartsWith("Access-Control-Allow", StringComparison.OrdinalIgnoreCase)))
                                {
                                    return null;
                                }

                                var stream = await response.Content.ReadAsStreamAsync();

                                // compute hash
                                var hash = HashAlgorithmPool.Sha256.ComputeHash(stream);
                                var base64 = Convert.ToBase64String(hash);
                                return $"sha256-{base64}";
                            }
                            catch (HttpRequestException)
                            {
                                return null;
                            }
                        });

                        // add attribute
                        if (sri != null)
                        {
                            context.AddChange(FastHtmlParser.CreateInsertAttributeChange(html, index, "script", "integrity", sri));
                            if (FastHtmlParser.GetAttributeValueAtTag(html, "crossorigin", index).Length == 0)
                            {
                                context.AddChange(FastHtmlParser.CreateInsertAttributeChange(html, index, "script", "crossorigin", "anonymous"));
                            }
                        }
                    }
                }
            }
        }

        private string RelativeTo(StringSegment value)
        {
            if (value.StartsWith("//", StringComparison.Ordinal))
            {
                return "https:" + value.Value;
            }

            return value.Value;
        }
    }
}