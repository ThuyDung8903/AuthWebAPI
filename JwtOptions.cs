namespace AuthWebAPI
{
    public class JwtOptions
    {
        public const string SectionName = "Jwt";
        public string? Key { get; set; }
        public string? Issuer { get; set; }
        public string? Audience { get; set; }
        public string? Subject { get; set; }
    }
}
