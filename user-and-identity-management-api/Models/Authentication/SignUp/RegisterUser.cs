using System.ComponentModel.DataAnnotations;

namespace user_and_identity_management_api.Models.Authentication.SignUp
{
    public class RegisterUser
    {
        [Required(ErrorMessage = "User Name is requred")]
        public string? UserName { get; set; }
        
        [EmailAddress]
        [Required(ErrorMessage = "Email is requred")]
        public string? Email { get; set; }
        
        [Required(ErrorMessage = "Password is requred")]
        public string? Password { get; set; }
    }
}
