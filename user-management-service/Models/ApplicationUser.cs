using Microsoft.AspNetCore.Identity;

namespace user_management_service.Models
{
    public class ApplicationUser : IdentityUser
    {
        public string? RefreshToken { get; set; }
        public DateTime RefreshTokenExpiry { get; set; }

       
    }
}