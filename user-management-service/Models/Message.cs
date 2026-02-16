
using MimeKit;

namespace user_management_service.Models
{
   public class Message
    {
        private string[] strings;
        private string v1;
        private string v2;

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

        public Message(string[] strings, string v1, string v2)
        {
            this.strings = strings;
            this.v1 = v1;
            this.v2 = v2;
        }
    }
}
