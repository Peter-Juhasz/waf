using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;

namespace Firewall.Tests
{
    [TestClass]
    public class BlacklistTests
    {
        [TestMethod]
        public async Task GetShExtension()
        {
            using var factory = new TestWebApplicationFactory();
            using var http = factory.CreateDefaultClient();

            using var response = await http.GetAsync("/x.sh");

            Assert.AreEqual(HttpStatusCode.Forbidden, response.StatusCode);
        }

        [TestMethod]
        public async Task GetSqlExtension()
        {
            using var factory = new TestWebApplicationFactory();
            using var http = factory.CreateDefaultClient();

            using var response = await http.GetAsync("/x.sql");

            Assert.AreEqual(HttpStatusCode.Forbidden, response.StatusCode);
        }

        [TestMethod]
        public async Task GetHtpasswd()
        {
            using var factory = new TestWebApplicationFactory();
            using var http = factory.CreateDefaultClient();

            using var response = await http.GetAsync("/.htpasswd");

            Assert.AreEqual(HttpStatusCode.Forbidden, response.StatusCode);
        }

        [TestMethod]
        public async Task GetGitFolder()
        {
            using var factory = new TestWebApplicationFactory();
            using var http = factory.CreateDefaultClient();

            using var response = await http.GetAsync("/.git/HEAD");

            Assert.AreEqual(HttpStatusCode.Forbidden, response.StatusCode);
        }

        [TestMethod]
        public async Task XScannerHeader()
        {
            using var factory = new TestWebApplicationFactory();
            using var http = factory.CreateDefaultClient();

            using var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.TryAddWithoutValidation("X-Scanner", "Test");
            using var response = await http.SendAsync(request);

            Assert.AreEqual(HttpStatusCode.Forbidden, response.StatusCode);
        }

        [TestMethod]
        public async Task UserAgentHeader()
        {
            using var factory = new TestWebApplicationFactory();
            using var http = factory.CreateDefaultClient();

            using var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.TryAddWithoutValidation("User-Agent", "acunetix");
            using var response = await http.SendAsync(request);

            Assert.AreEqual(HttpStatusCode.Forbidden, response.StatusCode);
        }
    }
}
