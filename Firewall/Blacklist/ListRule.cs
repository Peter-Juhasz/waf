namespace Firewall
{
    public class ListRule
    {
        public string? Id { get; set; }
        public string Term { get; set; }
        public MatchMode? MatchMode { get; set; }
        public string? Category { get; set; }
        public string? Description { get; set; }
        public string[]? Tags { get; set; }
        public string[]? References { get; set; }
        public LocationKind[]? Locations { get; set; }
    }
}
