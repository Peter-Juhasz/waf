using System;
using System.Collections.Generic;

namespace Firewall
{
    public class Rule
    {
        public Rule(string id, string category, string? description = null, IReadOnlyCollection<string>? tags = null)
        {
            Id = id;
            Category = category;
            Description = description;
            Tags = tags ?? Array.Empty<string>();
        }

        public string Id { get; }
        public string Category { get; }
        public string? Description { get; }
        public IReadOnlyCollection<string> Tags { get; }
    }
}
