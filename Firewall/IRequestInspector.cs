using System.Threading;

namespace Firewall
{
    public interface IRequestInspector
    {
        void Inspect(RequestAnalysisContext context, CancellationToken cancellationToken);
    }
}
