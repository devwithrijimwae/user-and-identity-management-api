using System.ComponentModel.DataAnnotations;

namespace user_management_Service.Models.Authentication.Login
{
    public class LoginModel
    {
        public readonly string? Email;

        [Required(ErrorMessage ="User Name Is required")]
        public required string UserName { get; set; }
        [Required(ErrorMessage = "Password Is required")]
            public required string Password { get; set; }
    }
}

