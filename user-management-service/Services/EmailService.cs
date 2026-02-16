using MailKit.Net.Smtp;
using MimeKit;
using user_management_service.Models;

namespace user_management_service.Services
{
    public class EmailService : IEmailService

    {
        private readonly EmailConfiguration _emailConfig;


        public EmailService(EmailConfiguration emailConfig)
        {
            _emailConfig = emailConfig;

        }

        public void SendEmail(Message message)
        {


            var emailMessage = CreateEmailMessage(message);
            sendEmail(emailMessage);

        }
        public MimeMessage CreateEmailMessage(Message message)
        {
            var emailMessage = new MimeMessage();
            emailMessage.From.Add(new MailboxAddress("email", _emailConfig.From));
            emailMessage.To.AddRange(message.To);
            emailMessage.Subject = message.Subject;
            emailMessage.Body = new TextPart(MimeKit.Text.TextFormat.Html) { Text = message.Content };
            return emailMessage;
        }
        public void sendEmail(MimeMessage emailMessage)
        {
            using var client = new SmtpClient();

            try
            {
                client.Connect(_emailConfig.SmtpServer, _emailConfig.Port, true);
                client.AuthenticationMechanisms.Remove("XOAUTH2");
                client.Authenticate(_emailConfig.Username, _emailConfig.Password);

                client.Send(emailMessage);
            }
            catch (Exception ex)
            {
                //log an error message or throw an exception or both.
                Console.WriteLine($"Error sending email: {ex.Message}");
            }
            finally
            {
                client.Disconnect(true);
                client.Dispose();
            }
        }

      
    }
}
