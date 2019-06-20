using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Net;
using System.Threading.Tasks;

namespace Firewall.Tests
{
    [TestClass]
    public class InformationDisclosureTests
    {
        [TestMethod]
        public async Task RemoveServerHeader()
        {
            using var factory = new TestWebApplicationFactory(async context =>
            {
                context.Response.Headers["Server"] = "Test";
                context.Response.StatusCode = 204;
            });
            using var http = factory.CreateDefaultClient();

            using var response = await http.GetAsync("/");

            Assert.AreEqual(HttpStatusCode.NoContent, response.StatusCode);
            Assert.IsFalse(response.Headers.Contains("Server"));
        }

        [TestMethod]
        public async Task RemoveXPoweredByHeader()
        {
            using var factory = new TestWebApplicationFactory(async context =>
            {
                context.Response.Headers["X-Powered-By"] = "Test";
                context.Response.StatusCode = 204;
            });
            using var http = factory.CreateDefaultClient();

            using var response = await http.GetAsync("/");

            Assert.AreEqual(HttpStatusCode.NoContent, response.StatusCode);
            Assert.IsFalse(response.Headers.Contains("Server"));
        }

        [TestMethod]
        public async Task RemoveGeneratorHtmlTag()
        {
            using var factory = new TestWebApplicationFactory(async context =>
            {
                await context.Response.SetBodyFromStringAsync("<!DOCTYPE html><html><head><meta name=\"generator\" value=\"test\" /></head><body>Hello world!</body></html>", "text/html");
            });
            using var http = factory.CreateDefaultClient();

            using var response = await http.GetAsync("/");

            Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
            Assert.AreEqual("<!DOCTYPE html><html><head></head><body>Hello world!</body></html>", await response.Content.ReadAsStringAsync());
        }

        [TestMethod]
        public async Task RemoveComments()
        {
            using var factory = new TestWebApplicationFactory(async context =>
            {
                await context.Response.SetBodyFromStringAsync("<!DOCTYPE html><html><body>Hello world!<!-- secret comment --></body></html>", "text/html");
            });
            using var http = factory.CreateDefaultClient();

            using var response = await http.GetAsync("/");

            Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
            Assert.AreEqual("<!DOCTYPE html><html><body>Hello world!</body></html>", await response.Content.ReadAsStringAsync());
        }

        [TestMethod]
        public async Task RemoveCommentsExceptIE()
        {
            using var factory = new TestWebApplicationFactory(async context =>
            {
                await context.Response.SetBodyFromStringAsync("<!DOCTYPE html><!--[if lt IE 7]> <html class=\"ie6 ie\"> <![endif]--><html><body>Hello world!<!-- secret comment --></body></html>", "text/html");
            });
            using var http = factory.CreateDefaultClient();

            using var response = await http.GetAsync("/");

            Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
            Assert.AreEqual("<!DOCTYPE html><!--[if lt IE 7]> <html class=\"ie6 ie\"> <![endif]--><html><body>Hello world!</body></html>", await response.Content.ReadAsStringAsync());
        }

        [TestMethod]
        public async Task RemoveCommentsExceptKnockout()
        {
            using var factory = new TestWebApplicationFactory(async context =>
            {
                await context.Response.SetBodyFromStringAsync("<!DOCTYPE html><html><body><!-- ko if: true -->Hello world!<!-- /ko --><!-- secret comment --></body></html>", "text/html");
            });
            using var http = factory.CreateDefaultClient();

            using var response = await http.GetAsync("/");

            Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
            Assert.AreEqual("<!DOCTYPE html><html><body><!-- ko if: true -->Hello world!<!-- /ko --></body></html>", await response.Content.ReadAsStringAsync());
        }
    }
}
