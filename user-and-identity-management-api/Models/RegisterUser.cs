using System.ComponentModel.DataAnnotations;

namespace user_and_identity_management_api.Models
{
    public class RegisterUser
    {
        [Required(ErrorMessage = "User Name is Required")]
        public string? UserName { get; set; }
        [Required(ErrorMessage = "User Email is Required")]
        public string? Email { get; set; }  
        [Required(ErrorMessage = "User Password is Required")]
        public string? Password { get; set; }
        [Required(ErrorMessage = "User Role is Required")]
        public string? Roles { get; set; }



    }

}
