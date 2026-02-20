using Microsoft.AspNetCore.Identity;
using user_management_service.Models;
using user_management_Service.Models.Authentication.Login;
using user_management_Service.Models.Authentication.SignUp;

namespace user_management_service.Services
{
    public class UserManagement : IUserManagement
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly RoleManager<IdentityRole> _roleManager;

        public UserManagement(
            UserManager<IdentityUser> userManager,
            SignInManager<IdentityUser> signInManager,
            RoleManager<IdentityRole> roleManager)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _roleManager = roleManager;
        }

        public async Task<ApiResponse<string>> CreateUserAsync(RegisterUser registerUser)
        {
            var response = new ApiResponse<string>();

            var user = new IdentityUser
            {
                UserName = registerUser.Email,
                Email = registerUser.Email
            };

            var result = await _userManager.CreateAsync(RegisterUser registerUser);

            if (!result.Succeeded)
            {
                response.IsSuccess = false;
                response.StatusCode = 400;
                response.Message = string.Join(", ", result.Errors.Select(e => e.Description));
                return response;
            }

            // Create role if it doesn't exist
            if (!await _roleManager.RoleExistsAsync(registerUser.Role))
            {
                await _roleManager.CreateAsync(new IdentityRole(registerUser.Role));
            }

            await _userManager.AddToRoleAsync(user, registerUser.Role);

            response.IsSuccess = true;
            response.StatusCode = 200;
            response.Message = "User created successfully";
            response.Data = registerUser.Role;

            return response;
        }

        public async Task<ApiResponse<string>> LoginUserAsync(LoginModel loginModel)
        {
            var response = new ApiResponse<string>();

            var user = await _userManager.FindByEmailAsync(loginModel.Email);

            if (user == null)
            {
                response.IsSuccess = false;
                response.StatusCode = 404;
                response.Message = "User not found";
                return response;
            }

            var result = await _signInManager.CheckPasswordSignInAsync(user, loginModel.Password, false);

            if (!result.Succeeded)
            {
                response.IsSuccess = false;
                response.StatusCode = 401;
                response.Message = "Invalid credentials";
                return response;
            }

            var roles = await _userManager.GetRolesAsync(user);

            response.IsSuccess = true;
            response.StatusCode = 200;
            response.Message = "Login successful";
            response.Data = roles.FirstOrDefault();

            return response;
        }

        public async Task<ApiResponse<List<string>>> GetUserRolesAsync(string email)
        {
            var response = new ApiResponse<List<string>>();

            var user = await _userManager.FindByEmailAsync(email);

            if (user == null)
            {
                response.IsSuccess = false;
                response.StatusCode = 404;
                response.Message = "User not found";
                return response;
            }

            var roles = await _userManager.GetRolesAsync(user);

            response.IsSuccess = true;
            response.StatusCode = 200;
            response.Message = "Roles fetched successfully";
            response.Data = roles.ToList();

            return response;
        }
    }
}