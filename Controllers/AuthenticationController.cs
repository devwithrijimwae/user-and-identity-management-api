using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using user_and_identity_management_api.Models;
using user_and_identity_management_api.Models.Authentication.SingUp;

namespace user_and_identity_management_api.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;
        public AuthenticationController(UserManager<IdentityUser> userManager, RoleManager<IdentityRole> roleManager, IConfiguration configuration)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
        }
        [HttpPost]
        [Route("Register")]
        public async Task<IActionResult> Register([FromBody] RegisterUser registeruser, string role)
        {
            //check User Exist
            var userExist = await _userManager.FindByEmailAsync(registeruser.Email);
            if (userExist == null) 
            {
                return StatusCode(StatusCodes.Status403Forbidden,
                    new Response { Status = "Error", Message = "User already exists" });  
            }
            //Add user in the data list
            IdentityUser user = new()
            {
                Email = registeruser.Email,
               SecurityStamp = Guid.NewGuid().ToString(),
                UserName = registeruser.UserName,
                
            };
            var Result = await _userManager.CreateAsync(user, password: registeruser.Password);
            if (Result.Succeeded) 
            {
                return StatusCode(StatusCodes.Status201Created,
                    new Response { Status = "Success", Message = "User created successfully" });
                
            }
            else
            {
                return StatusCode(StatusCodes.Status500InternalServerError,
                    new Response { Status = "Error", Message = "User creation failed to create"});
            }
            // Asign a role 

        }
    }
}
