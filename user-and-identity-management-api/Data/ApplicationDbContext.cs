using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using user_management_service.Models;

namespace user_and_identity_management_api.Data
{
    public class ApplicationDbContext
        : IdentityDbContext<ApplicationUser>
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }
        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);
        }
        private void SeedRoles(ModelBuilder builder)
        {
            builder.Entity<IdentityRole>().HasData(
                new IdentityRole { Name = "Admin",ConcurrencyStamp = "1", NormalizedName = "ADMIN" },
                new IdentityRole { Name = "User", ConcurrencyStamp = "2", NormalizedName = "USER" },
                new IdentityRole {Name = "HR", ConcurrencyStamp ="3",NormalizedName = "HR" }
            );
        }
    }
}
