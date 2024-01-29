using System.ComponentModel.DataAnnotations;
using System.Text.RegularExpressions;

namespace Assignment.ViewModels
{
    public class Register
    {
		[Required]
		[DataType(DataType.Text)]
		public string FirstName { get; set; }
		[Required]
		[DataType(DataType.Text)]
		public string LastName { get; set; }
		[Required]
		[DataType(DataType.CreditCard)]
		public string CreditCardNo { get; set; }
		[Required]
		[DataType(DataType.PhoneNumber)]
		public string MobileNo { get; set; }
		[Required]
		[DataType(DataType.Text)]
		public string BillingAddress { get; set; }
		[Required]
		[DataType(DataType.Text)]
		public string ShippingAddress { get; set; }
		[Required]
		[DataType(DataType.EmailAddress)]
		public string EmailAddress { get; set; }
		[Required]
		[DataType(DataType.Password)]
		public string Password { get; set; }
		[Required]
		[DataType(DataType.Password)]
		public string ConfirmPassword { get; set; }

		// TODO: Add photo
		[Required]
		public IFormFile Image { get; set; }
	}
}
