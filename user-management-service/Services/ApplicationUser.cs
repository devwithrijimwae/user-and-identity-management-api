
using System.Security.Claims;

namespace User.Management.Service.Services
{
    public class ApplicationUser
    {
        public string? RefreshToken { get; internal set; }
        public DateTime RefreshTokenExpiry { get; internal set; }
        public ClaimsIdentity? UserName { get; internal set; }
        public bool TwoFactorEnabled { get; internal set; }
        public object? Email { get; internal set; }
        public string? Id { get; internal set; }

        public static implicit operator ApplicationUser(ApplicationUser v)
        {
            throw new NotImplementedException();
        }
    }
}