using BenchmarkDotNet.Running;
using System;

namespace Firewall.Benchmark
{
    class Program
    {
        static void Main(string[] args)
        {
            BenchmarkRunner.Run<MiddlewareBenchmark>();
        }
    }
}
