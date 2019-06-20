using System.Collections.Generic;

namespace Firewall
{
    public class FirewallOptions
    {
        public FirewallMode Mode { get; set; } = FirewallMode.Prevention;

        public int DeniedResponseStatusCode { get; set; } = 403;

        public AnalysisDepth Depth { get; set; } = AnalysisDepth.FindFirst;

        public ISet<string>? IncludedTags { get; set; }

        public ISet<string>? ExcludedTags { get; set; }
    }
}
