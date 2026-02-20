using user_management_service.Models;
using user_management_Service.Models.Authentication.Login;
using user_management_Service.Models.Authentication.SignUp;

namespace user_management_service.Services
{
    public interface IUserManagement
    {
        Task<ApiResponse<string>> CreateUserWithTokenAsync(RegisterUser registerUser);
        Task<ApiResponse<string>> AssignRoleToUserAsync(string userId, string role);
        Task<ApiResponse<string>> GetOtpByLoginAsync(LoginModel loginModel);
        Task CreateUserAsync(RegisterUser registerUser);
    }
}