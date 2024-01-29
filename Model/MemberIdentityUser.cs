using Microsoft.AspNetCore.Identity;

namespace Assignment.Model
{
	public class MemberIdentityUser : IdentityUser
	{
		public byte[] FirstName { get; set; }
		public byte[] LastName { get; set; }
		public byte[] CreditCardNo { get; set; }
		public byte[] BillingAddress { get; set; }
		public byte[] ShippingAddress { get; set; }
		public byte[] MobileNumber { get; set; }
		public string? ImagePath { get; set;}
	}
}
