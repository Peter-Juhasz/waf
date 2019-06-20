using Microsoft.Extensions.Primitives;
using System;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Threading;

namespace Firewall
{
    public class DecompressionInspector : IResponseInspector
    {
        private static readonly char[] Separators = new[] { ',' };

        public void Inspect(ResponseAnalysisContext context, CancellationToken cancellationToken)
        {
            if (context.Response.Headers.TryGetValue("Content-Encoding", out var contentEncoding))
            {
                foreach (var encoding in contentEncoding.SelectMany(v => new StringTokenizer(v, Separators)))
                {
                    if (encoding.Equals("gzip", StringComparison.OrdinalIgnoreCase))
                    {
                        using var gzip = new GZipStream(context.ReadAsStream().Rewind(), CompressionMode.Decompress, leaveOpen: true);
                        var buffer = new MemoryStream();
                        gzip.CopyTo(buffer);
                        context.SetBodyFromStream(buffer.Rewind());
                    }
                    else if (encoding.Equals("deflate", StringComparison.OrdinalIgnoreCase))
                    {
                        using var gzip = new DeflateStream(context.ReadAsStream().Rewind(), CompressionMode.Decompress, leaveOpen: true);
                        var buffer = new MemoryStream();
                        gzip.CopyTo(buffer);
                        context.SetBodyFromStream(buffer.Rewind());
                    }
                    else if (encoding.Equals("br", StringComparison.OrdinalIgnoreCase))
                    {
                        using var gzip = new BrotliStream(context.ReadAsStream().Rewind(), CompressionMode.Decompress, leaveOpen: true);
                        var buffer = new MemoryStream();
                        gzip.CopyTo(buffer);
                        context.SetBodyFromStream(buffer.Rewind());
                    }
                }
            }
        }
    }
}
