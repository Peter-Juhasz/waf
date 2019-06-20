using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Firewall
{
    public static class StreamExtensions
    {
        public static Stream Rewind(this Stream stream)
        {
            stream.Position = 0L;
            return stream;
        }

        public static bool Contains(this StringSegment segment, char ch) => segment.IndexOf(ch) != -1;

        public static bool Contains(this StringSegment segment, string str) => Contains(segment, str, StringComparison.Ordinal);

        public static bool Contains(this StringSegment segment, string str, StringComparison comparison)
        {
            int idx = segment.Buffer.IndexOf(str, segment.Offset, comparison);
            if (idx == -1)
                return false;

            return idx <= segment.Offset + segment.Length - str.Length;
        }

        public static StringSegment TrimHtmlCdata(this StringSegment segment)
        {
            if (segment.StartsWith("<!--//--><![CDATA[//><!--", StringComparison.Ordinal))
            {
                segment = segment.Subsegment("<!--//--><![CDATA[//><!--".Length);
            }
            else if (segment.StartsWith("<!--/*--><![CDATA[/*><!--*/", StringComparison.Ordinal))
            {
                segment = segment.Subsegment("<!--/*--><![CDATA[/*><!--*/".Length);
            }

            if (segment.EndsWith("//--><!]]>", StringComparison.Ordinal))
            {
                segment = segment.Subsegment(0, segment.Length - "//--><!]]>".Length);
            }
            else if (segment.EndsWith("/*]]>*/-->", StringComparison.Ordinal))
            {
                segment = segment.Subsegment(0, segment.Length - "/*]]>*/-->".Length);
            }

            return segment;
        }


        public static async Task SetBodyFromStringAsync(this HttpResponse response, string body, string contentType = "text/plain")
        {
            var buffer = Encoding.UTF8.GetBytes(body);
            response.ContentLength = buffer.Length;
            response.ContentType = contentType;
            response.StatusCode = 200;
            await response.Body.WriteAsync(buffer, 0, buffer.Length);
        }


        public static Rule With(this Rule rule, ListRule listRule)
        {
            if (listRule.Id == null && (listRule.Category == rule.Category || listRule.Category == null) && !listRule.Tags.Any())
            {
                return rule;
            }

            return new Rule(listRule.Id ?? rule.Id, listRule.Category ?? rule.Category, listRule.Description ?? rule.Description, listRule.Tags ?? rule.Tags);
        }

        public static string ToHexString(this Span<byte> bytes)
        {
            if (HexLookupLowercase == null)
            {
                lock (HexLookupLock)
                {
                    if (HexLookupLowercase == null)
                    {
                        HexLookupLowercase = new string[256];
                        for (byte b = 0; b <= 255; b++)
                        {
                            HexLookupLowercase[b] = b.ToString("x2");

                            if (b == 255)
                            {
                                break;
                            }
                        }
                    }
                }
            }

            var sb = new InplaceStringBuilder(bytes.Length * 2);

            foreach (var b in bytes)
            {
                sb.Append(HexLookupLowercase[b]);
            }

            return sb.ToString();
        }

        private static string[] HexLookupLowercase;
        private static object HexLookupLock = new object();



        public static IEnumerable<int> AllIndexesOf(this string str, string subject, StringComparison comparison)
        {
            int index = str.IndexOf(subject, comparison);
            while (index != -1)
            {
                yield return index;
                index = str.IndexOf(subject, index + 1, comparison);
            }
        }
    }
}
