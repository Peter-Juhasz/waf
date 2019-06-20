namespace Firewall
{
    public class Diagnostic
    {
        public Diagnostic(Rule rule, Location location)
        {
            Rule = rule;
            Location = location;
        }

        public Rule Rule { get; }

        public Location Location { get;  }
    }
}
