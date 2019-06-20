using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;

namespace Firewall
{
    public class ResponseAnalysisContext
    {
        public ResponseAnalysisContext(HttpResponse response)
        {
            Response = response;
            streamContent = response.Body;
        }

        public HttpResponse Response { get; }

        public HttpContext HttpContext => Response.HttpContext;

        public int Version { get; private set; }

        public ResponseBodyType SnapshotBodyType { get; private set; } = ResponseBodyType.Stream;

        protected Queue<TextChange>? PendingChanges { get; set; }

        public bool IsMalicious => Diagnostics.Any();

        private ImmutableList<Diagnostic> diagnostics = ImmutableList<Diagnostic>.Empty;
        public IReadOnlyCollection<Diagnostic> Diagnostics => diagnostics;


        public bool IsHtmlOrCssOrJs()
        {
            if (Response.Headers.TryGetValue("Content-Type", out var contentType))
            {
                if (contentType.Any(c =>
                    c.StartsWith("text/html", StringComparison.OrdinalIgnoreCase) ||
                    c.StartsWith("text/css", StringComparison.OrdinalIgnoreCase) ||
                    c.StartsWith("text/javascript", StringComparison.OrdinalIgnoreCase) ||
                    c.StartsWith("application/javascript", StringComparison.OrdinalIgnoreCase)
                ))
                {
                    return true;
                }
            }

            return false;
        }

        public bool IsTextLike()
        {
            if (Response.Headers.TryGetValue("Content-Type", out var contentType))
            {
                if (contentType.Any(c =>
                    c.StartsWith("text/", StringComparison.OrdinalIgnoreCase) ||
                    c.StartsWith("application/json", StringComparison.OrdinalIgnoreCase) ||
                    c.StartsWith("application/javascript", StringComparison.OrdinalIgnoreCase)
                ))
                {
                    return true;
                }
            }

            return false;
        }

        public bool IsHtml() => Response.ContentType?.StartsWith("text/html", StringComparison.OrdinalIgnoreCase) ?? false;
        public bool IsCss() => Response.ContentType?.StartsWith("text/css", StringComparison.OrdinalIgnoreCase) ?? false;


        private string stringContent = null;
        private int stringVersion = -1;

        public string ReadAsString(bool applyPendingChanges = false)
        {
            if (SnapshotBodyType == ResponseBodyType.Stream)
            {
                if (stringVersion != Version)
                {
                    var contentType = Response.GetTypedHeaders().ContentType;
                    var enconding = contentType?.Encoding ?? Encoding.UTF8;

                    using var reader = new StreamReader(streamContent.Rewind(), enconding, true, 1024, leaveOpen: true);
                    stringContent = reader.ReadToEnd();
                    stringVersion = streamVersion;
                    SnapshotBodyType = ResponseBodyType.String;
                }
            }

            if (PendingChanges != null && PendingChanges.Count > 0 && applyPendingChanges)
            {
                var builder = new StringBuilder(stringContent);

                while (PendingChanges.TryDequeue(out var edit))
                {
                    edit.Apply(builder);

                    foreach (var remaining in PendingChanges)
                    {
                        remaining.AdjustBy(edit);
                    }
                }

                stringContent = builder.ToString();
                stringVersion = Version;
            }

            return stringContent;
        }

        public void AddChange(TextChange change)
        {
            if (SnapshotBodyType != ResponseBodyType.String)
            {
                throw new InvalidOperationException();
            }

            if (PendingChanges == null)
            {
                PendingChanges = new Queue<TextChange>(capacity: 16);
            }

            PendingChanges.Enqueue(change);
            Version++;
        }

        public void SetBodyFromString(string body)
        {
            stringContent = body;
            stringVersion = ++Version;
            SnapshotBodyType = ResponseBodyType.String;

            int length = Encoding.UTF8.GetByteCount(body);
            Response.ContentLength = length;
            Response.Headers["Content-Length"] = length.ToString(CultureInfo.InvariantCulture);

            if (Response.Headers.ContainsKey("Content-Encoding"))
            {
                Response.Headers.Remove("Content-Encoding");
            }

            if (Response.Headers.ContainsKey("Content-MD5"))
            {
                Response.Headers.Remove("Content-MD5");
            }
        }


        private Stream streamContent = null;
        private int streamVersion = 0;

        public Stream ReadAsStream()
        {
            if (SnapshotBodyType == ResponseBodyType.String)
            {
                if (streamVersion != Version)
                {
                    streamContent = new MemoryStream(Encoding.UTF8.GetBytes(stringContent));
                    streamVersion = stringVersion;
                    Response.RegisterForDispose(streamContent);
                }
            }

            return streamContent;
        }

        public void SetBodyFromStream(Stream body)
        {
            streamContent = body;
            streamVersion = ++Version;
            SnapshotBodyType = ResponseBodyType.Stream;

            Response.Body = body;
            Response.RegisterForDispose(body);

            Response.ContentLength = body.Length;
            Response.Headers["Content-Length"] = body.Length.ToString(CultureInfo.InvariantCulture);

            if (Response.Headers.ContainsKey("Content-Encoding"))
            {
                Response.Headers.Remove("Content-Encoding");
            }

            if (Response.Headers.ContainsKey("Content-MD5"))
            {
                Response.Headers.Remove("Content-MD5");
            }
        }

        public byte[] ReadAsByteArray()
        {
            return Array.Empty<byte>();
        }

        public void ReportDiagnostic(Diagnostic diagnostic)
        {
            diagnostics = diagnostics.Add(diagnostic);
        }
    }
}
