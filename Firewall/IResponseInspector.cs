
using System.Threading;

namespace Firewall
{
    public interface IResponseInspector
    {
        void Inspect(ResponseAnalysisContext context, CancellationToken cancellationToken);
    }
}
