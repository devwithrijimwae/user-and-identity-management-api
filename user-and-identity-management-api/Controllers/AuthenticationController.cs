using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using NETCore.MailKit.Core;
using user_and_identity_management_api.Models;
using user_and_identity_management_api.Models.Authentication.SignUp;
using user_management_service.Models;

namespace user_and_identity_management_api.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IEmailService _emailService;

        public AuthenticationController(UserManager<IdentityUser> userManager, RoleManager<IdentityRole> roleManager, IEmailService emailService)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _emailService = emailService;

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
            if (!Result.Succeeded)
            {
                return StatusCode(StatusCodes.Status201Created,
                    new Response { Status = "Success", Message = "User created successfully" });

            }
            else
            {
                return StatusCode(StatusCodes.Status500InternalServerError,
                    new Response { Status = "Error", Message = "User creation failed to create" });
            }
            if (await _roleManager.RoleExistsAsync(role))
            {
                var result = await _userManager.CreateAsync(user, password: registeruser.Password);
                if (!result.Succeeded)
                {

                }
                return StatusCode(StatusCodes.Status201Created,
                    new Response { Status = "Success", Message = "User created successfully" });

            }
            else
            {
                return StatusCode(StatusCodes.Status500InternalServerError,
                    new Response { Status = "Error", Message = "This role does not exist" });


            }

            if (await _roleManager.RoleExistsAsync(role))
            {
                var result = await _userManager.CreateAsync(user, password: registeruser.Password);
                if (!result.Succeeded)
                {
                    return StatusCode(StatusCodes.Status500InternalServerError,
                    new Response { Status = "Error", Message = "User failed to create" });
                }
            }
            //Add role to the User
            await _userManager.AddToRoleAsync(user, role);
            var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            var confirmationLink = Url.Action("ConfirmEmail", "Authentication", new { token, email = user.Email }, Request.Scheme);
            await _emailService.SendAsync(user.Email, "Email Confirmation", $"<h1> Please confirm your email by clicking on the link below: </h1><br><a href='{confirmationLink}'>Confirm Email</a>", isHtml: true);

            return StatusCode(StatusCodes.Status200OK,
                new Response { Status = "Success", Message = "User failled to create email successfully" });

        }

        [HttpGet]
        public IActionResult TestEmail()
        {
            var message =
                new Message(new string[]
                { "peacerijim@gmail.com" }, "Test", "<h1> Subcribe to  my channel! </>");

            return StatusCode(StatusCodes.Status200OK,
               new Response { Status = "Success", Message = "Email sent successfully" });

        }
        [HttpGet("ConfirmEmail")]
        public async Task<IActionResult> ConfirmEmail(string token, string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user != null)
            {
                var result = await _userManager.ConfirmEmailAsync(user, token);
                if (result.Succeeded)
                {
                    return StatusCode(StatusCodes.Status200OK,
                        new Response { Status = "Success", Message = "Email varified successfully" });
                }
                else
                {
                    return StatusCode(StatusCodes.Status500InternalServerError,
                        new Response { Status = "Error", Message = "This user does not exist" });

                }
            } else
            return StatusCode(StatusCodes.Status404NotFound,
        new Response { Status = "Error", Message = "User not found" });
        }
    }
}




