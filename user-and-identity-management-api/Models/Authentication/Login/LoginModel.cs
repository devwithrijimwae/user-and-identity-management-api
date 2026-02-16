using System.ComponentModel.DataAnnotations;

namespace user_and_identity_management_api.Models.Authentication.Login
{
    public class LoginModel
    {
        [Required(ErrorMessage ="User Name Is required")]
        public required string UserName { get; set; }
        [Required(ErrorMessage = "Password Is required")]
            public required string Password { get; set; }
    }
}

