using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Net;
using System.Threading.Tasks;

namespace Firewall.Tests
{
    [TestClass]
    public class HttpsTests
    {
        [TestMethod]
        public async Task RewriteLocationHeader()
        {
            using var factory = new TestWebApplicationFactory(async context =>
            {
                context.Response.Headers["Location"] = "http://example.org/";
                context.Response.StatusCode = 302;
            });
            using var http = factory.CreateDefaultClient();

            using var response = await http.GetAsync("/");

            Assert.AreEqual(HttpStatusCode.Redirect, response.StatusCode);
            Assert.AreEqual("https://example.org/", response.Headers.Location.ToString());
        }

        [TestMethod]
        public async Task RewriteATag()
        {
            using var factory = new TestWebApplicationFactory(async context =>
            {
                await context.Response.SetBodyFromStringAsync("<!DOCTYPE html><html><body><a href=\"http://example.org\">Click</a></body></html>", "text/html");
            });
            using var http = factory.CreateDefaultClient();

            using var response = await http.GetAsync("/");

            Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
            Assert.AreEqual("<!DOCTYPE html><html><body><a href=\"https://example.org\">Click</a></body></html>", await response.Content.ReadAsStringAsync());
        }

        [TestMethod]
        public async Task RewriteScriptTag()
        {
            using var factory = new TestWebApplicationFactory(async context =>
            {
                await context.Response.SetBodyFromStringAsync("<!DOCTYPE html><html><head><script src=\"http://example.org\"></script></head></html>", "text/html");
            });
            using var http = factory.CreateDefaultClient();

            using var response = await http.GetAsync("/");

            Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
            Assert.AreEqual("<!DOCTYPE html><html><head><script src=\"https://example.org\"></script></head></html>", await response.Content.ReadAsStringAsync());
        }

        [TestMethod]
        public async Task RewriteStyleTag()
        {
            using var factory = new TestWebApplicationFactory(async context =>
            {
                await context.Response.SetBodyFromStringAsync("<!DOCTYPE html><html><head><link type=\"text/css\" rel=\"stylesheet\" href=\"http://example.org\" /></head></html>", "text/html");
            });
            using var http = factory.CreateDefaultClient();

            using var response = await http.GetAsync("/");

            Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
            Assert.AreEqual("<!DOCTYPE html><html><head><link type=\"text/css\" rel=\"stylesheet\" href=\"https://example.org\" /></head></html>", await response.Content.ReadAsStringAsync());
        }

        [TestMethod]
        public async Task DoesNotRewriteXmlns()
        {
            using var factory = new TestWebApplicationFactory(async context =>
            {
                await context.Response.SetBodyFromStringAsync("<!DOCTYPE html><html xmlns=\"http://www.w3.org/TR/html4/\"><head><link type=\"text/css\" rel=\"stylesheet\" href=\"http://example.org\" /></head></html>", "text/html");
            });
            using var http = factory.CreateDefaultClient();

            using var response = await http.GetAsync("/");

            Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
            Assert.AreEqual("<!DOCTYPE html><html xmlns=\"http://www.w3.org/TR/html4/\"><head><link type=\"text/css\" rel=\"stylesheet\" href=\"https://example.org\" /></head></html>", await response.Content.ReadAsStringAsync());
        }
    }
}
