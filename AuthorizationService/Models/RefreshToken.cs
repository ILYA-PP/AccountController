using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace AuthorizationService.Models
{
    public class RefreshToken
    {
        [Key]
        [JsonIgnore]
        public int Id { get; set; }

        [JsonIgnore]
        public int UserId { get; set; }

        [ForeignKey("UserId")]
        public User User { get; set; }
        public string Token { get; set; }
        public DateTime Expires { get; set; }
        public DateTime Created { get; set; }
        public DateTime? Revoked { get; set; }
        public string ReplacedByToken { get; set; }

        [NotMapped]
        public bool IsExpired => DateTime.UtcNow >= Expires;
        [NotMapped]
        public bool IsActive => Revoked == null && !IsExpired;
    }
}
