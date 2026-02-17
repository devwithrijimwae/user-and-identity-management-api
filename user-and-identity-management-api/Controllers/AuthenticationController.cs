using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using NETCore.MailKit.Core;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using user_and_identity_management_api.Models;
using user_and_identity_management_api.Models.Authentication.Login;
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
        private readonly IConfiguration _configuration;
        private readonly SignInManager<IdentityUser> _signInManager;

        public AuthenticationController(
    UserManager<IdentityUser> userManager,
    RoleManager<IdentityRole> roleManager,
    IEmailService emailService,
    IConfiguration configuration,
    SignInManager<IdentityUser> signInManager) // <-- Add <IdentityUser> here
{
            _userManager = userManager;
            _roleManager = roleManager;
            _signInManager = signInManager;
            _emailService = emailService;
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
                TwoFactorEnabled = true

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
                new Response { Status = "Success", Message = $"User created & email sent to {user.Email} successfully" });

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

        [HttpPost]
        [Route("Login")]
        public async Task<IActionResult> Login([FromBody] LoginModel loginModel)
        {
            //check if the user exists
            var user = await _userManager.FindByNameAsync(loginModel.UserName);
            if (user != null && await _userManager.CheckPasswordAsync(user, loginModel.Password))
            {
                //claimlist creation 
                var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.UserName),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                };
                //add role to the list of claims
                var userRoles = await _userManager.GetRolesAsync(user);
                foreach (var role in userRoles)
                {
                    authClaims.Add(new Claim(ClaimTypes.Role, role));
                }
                if (user.TwoFactorEnabled)
                {
                    await _signInManager.SignOutAsync();
                    await _signInManager.PasswordSignInAsync(user, loginModel.Password, false, true);
                    var token = await _userManager.GenerateTwoFactorTokenAsync(user, "Email");

                    // Send the token to the user's email
                    await _emailService.SendAsync(user.Email, "OTP Confirmation", token);

                    return StatusCode(StatusCodes.Status200OK,
                       new Response { Status = "Success", Message = $"we have sent an OTP to your Email {user.Email}" });
                }
                //generate token with the claims
                var jwttoken = GetToken(authClaims);
                //return the token

                return Ok(new
                {
                    token = new JwtSecurityTokenHandler().WriteToken(jwttoken),
                    expiration = jwttoken.ValidTo

                });

            }
            return Unauthorized();

        }
        private JwtSecurityToken GetToken(List<Claim> authClaims)
        {
            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));
            var token = new JwtSecurityToken(
                issuer: _configuration["JWT:ValidIssuer"],
                audience: _configuration["JWT:ValidAudience"],
                expires: DateTime.Now.AddHours(3),
                claims: authClaims,
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
                );
            return token;
        }
        [HttpPost("login-2FA")]
        [Route("login-2FA")]
        public async Task<IActionResult> LoginWithOTP(string code)
        {
            var user = await _userManager.GetUserAsync(User); // <-- Fix: get user from ClaimsPrincipal
            var signin = await _signInManager.TwoFactorAuthenticatorSignInAsync(code, false, false); // <-- Add await
            if (signin.Succeeded)
            {
                // You may need to provide loginModel.Password or refactor this block, but for now:
                // claimlist creation 
                var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.UserName),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                };
                // add role to the list of claims
                var userRoles = await _userManager.GetRolesAsync(user);
                foreach (var role in userRoles)
                {
                    authClaims.Add(new Claim(ClaimTypes.Role, role));
                }
                // generate token with the claims
                var jwttoken = GetToken(authClaims);
                // return the token
                return Ok(new
                {
                    token = new JwtSecurityTokenHandler().WriteToken(jwttoken),
                    expiration = jwttoken.ValidTo
                });
            }
            return Unauthorized();
        }
    }
}




































































