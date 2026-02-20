using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using User.Management.Service.Models;
using User.Management.Service.Models.Authentication.User;
using user_management_Service.Models.Authentication.Login;
using user_management_Service.Models.Authentication.SignUp;

namespace User.Management.Service.Services
{
    public class UserManagement : IUserManagement
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;
        private readonly IEmailService _emailService;

        public object ClaimTypesUser { get; private set; }

        public UserManagement(UserManager<ApplicationUser> userManager,
                              SignInManager<ApplicationUser> signInManager,
                              RoleManager<IdentityRole> roleManager,
                              IConfiguration configuration,
                              IEmailService emailService)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _roleManager = roleManager;
            _configuration = configuration;
            _emailService = emailService;
        }

        #region User Creation & Role Assignment

        public async Task<ApiResponse<CreateUserResponse>> CreateUserWithTokenAsync(RegisterUser registerUser)
        {
            var userExist = await _userManager.FindByEmailAsync(registerUser.Email);
            if (userExist != null)
                return new ApiResponse<CreateUserResponse> { IsSuccess = false, StatusCode = 403, Message = "User already exists!" };

            var user = new ApplicationUser
            {
                Email = registerUser.Email,
                Id = Guid.NewGuid().ToString(),
                UserName = registerUser.UserName,
                TwoFactorEnabled = true
            };

            var result = await _userManager.CreateAsync(user, registerUser.Password);
            if (result.Succeeded)
            {
                var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                return new ApiResponse<CreateUserResponse>
                {
                    Response = new CreateUserResponse { User = user, Token = token },
                    IsSuccess = true,
                    StatusCode = 201,
                    Message = "User created."
                };
            }

            return new ApiResponse<CreateUserResponse>
            {
                IsSuccess = false,
                StatusCode = 500,
                Message = "User creation failed! Please check user details and try again."
            };
        }

        public async Task<ApiResponse<List<string>>> AssignRoleToUserAsync(string? role, ApplicationUser user)
        {
            var assignedRoles = new List<string>();
            if (!string.IsNullOrEmpty(role))
            {
                if (await _roleManager.RoleExistsAsync(role))
                {
                    if (!await _userManager.IsInRoleAsync(user, role))
                    {
                        await _userManager.AddToRoleAsync(user, role);
                        assignedRoles.Add(role);
                    }
                }
            }
            return new ApiResponse<List<string>>
            {
                IsSuccess = true,
                StatusCode = 200,
                Message = "Role assigned successfully",
                Response = assignedRoles
            };
        }

        #endregion

        #region OTP & Login

        public async Task<ApiResponse<LoginOtpResponse>> GetOtpByLoginAsync(LoginModel loginModel)
        {
            var user = await _userManager.FindByNameAsync(loginModel.UserName);
            if (user == null)
                return new ApiResponse<LoginOtpResponse> { IsSuccess = false, StatusCode = 404, Message = "User does not exist." };

            await _signInManager.SignOutAsync();
            await _signInManager.PasswordSignInAsync(user, loginModel.Password, false, true);

            if (user.TwoFactorEnabled)
            {
                var token = await _userManager.GenerateTwoFactorTokenAsync(user, "Email");
                return new ApiResponse<LoginOtpResponse>
                {
                    Response = new LoginOtpResponse
                    {
                        User = user,
                        Token = token,
                        IsTwoFactorEnable = true
                    },
                    IsSuccess = true,
                    StatusCode = 200,
                    Message = $"OTP sent to the email {user.Email}"
                };
            }

            return new ApiResponse<LoginOtpResponse>
            {
                Response = new LoginOtpResponse
                {
                    User = user,
                    Token = string.Empty,
                    IsTwoFactorEnable = false
                },
                IsSuccess = false,
                StatusCode = 400,
                Message = $"Two factor authentication is not enabled for user {user.UserName}"
            };
        }

        public async Task<ApiResponse<LoginResponse>> LoginUserWithJWTokenAsync(string otp, string userName)
        {
            var user = await _userManager.FindByNameAsync(userName);
            if (user == null)
                return new ApiResponse<LoginResponse> { IsSuccess = false, StatusCode = 404, Message = "User not found" };

            var signIn = await _signInManager.TwoFactorSignInAsync("Email", otp, false, false);
            if (!signIn.Succeeded)
                return new ApiResponse<LoginResponse> { IsSuccess = false, StatusCode = 400, Message = "Invalid OTP" };

            return await GetJwtTokenAsync(user);
        }

        #endregion

        #region JWT Token & Refresh Token

        public async Task<ApiResponse<LoginResponse>> GetJwtTokenAsync(ApplicationUser user)
        {
            var authClaims = new List<Claim>
            {
               new Claim(ClaimTypes.Surname, user.UserName),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            };

            var userRoles = await _userManager.GetRolesAsync(user);
            foreach (var role in userRoles)
                authClaims.Add(new Claim(ClaimTypes.Role, role));

            var jwtToken = GetToken(authClaims);
            var refreshToken = GenerateRefreshToken();

            _ = int.TryParse(_configuration["JWT:RefreshTokenValidity"], out int refreshTokenValidity);

            user.RefreshToken = refreshToken;
            user.RefreshTokenExpiry = DateTime.UtcNow.AddDays(refreshTokenValidity);

            await _userManager.UpdateAsync(user);

            return new ApiResponse<LoginResponse>
            {
                Response = new LoginResponse
                {
                    AccessToken = new TokenType
                    {
                        Token = new JwtSecurityTokenHandler().WriteToken(jwtToken),
                        ExpiryTokenDate = jwtToken.ValidTo
                    },
                    RefreshToken = new TokenType
                    {
                        Token = user.RefreshToken,
                        ExpiryTokenDate = (DateTime)user.RefreshTokenExpiry
                    }
                },
                IsSuccess = true,
                StatusCode = 200,
                Message = "Token created"
            };
        }

        public async Task<ApiResponse<LoginResponse>> RenewAccessTokenAsync(LoginResponse tokens)
        {
            var principal = GetClaimsPrincipal(tokens.AccessToken.Token);
            var user = await _userManager.FindByNameAsync(principal.Identity.Name);
            if (tokens.RefreshToken.Token != user.RefreshToken || tokens.RefreshToken.ExpiryTokenDate <= DateTime.UtcNow)
            {
                return new ApiResponse<LoginResponse> { IsSuccess = false, StatusCode = 400, Message = "Token invalid or expired" };
            }

            return await GetJwtTokenAsync(user);
        }

        #endregion

        #region Private Methods

        private JwtSecurityToken GetToken(List<Claim> authClaims)
        {
            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));
            _ = int.TryParse(_configuration["JWT:TokenValidityInMinutes"], out int tokenValidityInMinutes);
            var expirationUtc = DateTime.UtcNow.AddMinutes(tokenValidityInMinutes);

            return new JwtSecurityToken(
                issuer: _configuration["JWT:ValidIssuer"],
                audience: _configuration["JWT:ValidAudience"],
                expires: expirationUtc,
                claims: authClaims,
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
            );
        }

        private string GenerateRefreshToken()
        {
            var randomNumber = new byte[64];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }

        private ClaimsPrincipal GetClaimsPrincipal(string accessToken)
        {
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"])),
                ValidateLifetime = false
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            return tokenHandler.ValidateToken(accessToken, tokenValidationParameters, out SecurityToken _);
        }

        public Task<ApiResponse<List<string>>> AssignRoleToUserAsync(List<string> roles, ApplicationUser user)
        {
            throw new NotImplementedException();
        }

        Task IUserManagement.AssignRoleToUserAsync(string? role, ApplicationUser user)
        {
            return AssignRoleToUserAsync(role, user);
        }

        #endregion
    }
}