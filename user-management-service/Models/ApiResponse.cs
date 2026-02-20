using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace user_management_service.Models
{
   public class ApiResponse<T>
    {
        internal string Roles;

        public bool IsSuccess { get; set; }
        public string? Message { get; set; }
        public int StatusCode { get; set; }
        public T? Data { get; set; }
 
    }
}
