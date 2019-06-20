using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;

namespace Firewall
{
    public class ProxyMiddleware : IMiddleware
    {
        public ProxyMiddleware(
            HttpClient httpClient,
            IOptions<ProxyOptions> options
        )
        {
            HttpClient = httpClient;
            Options = options;
        }

        public HttpClient HttpClient { get; }
        public IOptions<ProxyOptions> Options { get; }

        public async Task InvokeAsync(HttpContext context, RequestDelegate next)
        {
            using var requestMessage = new HttpRequestMessage();
            requestMessage.Method = new HttpMethod(context.Request.Method);
            var options = Options.Value;
            requestMessage.RequestUri = new Uri(options.Scheme + "://" + options.Host + context.Request.Path + context.Request.QueryString);

            // copy headers
            foreach (var header in context.Request.Headers.Where(h => h.Key != "Host"))
            {
                requestMessage.Headers.TryAddWithoutValidation(header.Key, header.Value as IEnumerable<string>);
            }

            // request content without compression
            if (requestMessage.Headers.Contains("Accept-Encoding"))
            {
                requestMessage.Headers.Remove("Accept-Encoding");
                requestMessage.Headers.TryAddWithoutValidation("Accept-Encoding", "identity");
            }

            // copy body
            if (context.Request.Body != null)
            {
                requestMessage.Content = new StreamContent(context.Request.Body);
            }

            // send request
            using var responseMessage = await HttpClient.SendAsync(requestMessage);

            // copy status code
            context.Response.StatusCode = (int)responseMessage.StatusCode;

            // copy headers
            foreach (var header in responseMessage.Headers.Where(h => h.Key != "Connection" && h.Key != "Transfer-Encoding"))
            {
                context.Response.Headers.Add(header.Key, new StringValues(header.Value.ToArray()));
            }

            // copy body
            if (responseMessage.Content != null)
            {
                // copy headers
                foreach (var header in responseMessage.Content.Headers.Where(h => h.Key != "Connection" && h.Key != "Transfer-Encoding"))
                {
                    context.Response.Headers.Add(header.Key, new StringValues(header.Value.ToArray()));
                }

                // copy body
                using var stream = await responseMessage.Content.ReadAsStreamAsync();
                await stream.CopyToAsync(context.Response.Body);
            }
        }
    }
}
