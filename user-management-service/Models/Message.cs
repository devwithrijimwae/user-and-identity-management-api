
using MimeKit;

namespace user_management_service.Models
{
   public class Message
    {
        public List<MailboxAddress> To { get; set; }
        public string Subject { get; set; }
        public string Content { get; set; }
        public Message(IEnumerable<string> to, string subject, string content, string x)
        {
            To = new List<MailboxAddress>();
            To.AddRange(to.Select(X => new MailboxAddress("email", x)));
            Subject = subject;
            Content = content;

        }
    }
}
