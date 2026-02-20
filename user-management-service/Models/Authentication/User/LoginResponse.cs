namespace User.Management.Service.Models.Authentication.User
{
    public class LoginResponse
    {
        public required TokenType AccessToken { get; set; }
        public required TokenType RefreshToken { get; set; }

    }
}