using BenchmarkDotNet.Attributes;
using System.IO;
using System.Text;

namespace Firewall.Benchmark
{
    [InProcess]
    public class StreamReaderBenchmark
    {
        [GlobalSetup]
        public void Setup()
        {
            byte[] v = Encoding.UTF8.GetBytes(File.ReadAllText("reference.html"));
            ms = new MemoryStream(v, 0, v.Length, true, true);
        }

        MemoryStream ms;

        [Benchmark]
        public void UsingStreamReader()
        {
            using var reader = new StreamReader(ms.Rewind(), Encoding.UTF8, true, 1024, true);
            reader.ReadToEnd();
        }

        [Benchmark]
        public void UsingBuffer()
        {
            var buffer = ms.GetBuffer();
            Encoding.UTF8.GetString(buffer, 0, (int)ms.Length);
        }
    }
}
