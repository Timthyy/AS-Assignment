using Assignment.Model;
using Assignment.ViewModels;
using Microsoft.AspNetCore.CookiePolicy;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Primitives;
using System;
using System.Drawing;
using System.Security.Claims;
using System.Text;
using System.Text.RegularExpressions;

namespace Assignment.Pages
{
	public class RegisterModel : PageModel
	{
		private UserManager<MemberIdentityUser> userManager { get; }
		private SignInManager<MemberIdentityUser> signInManager { get; }
        private readonly IWebHostEnvironment _environment;

        private readonly ILogger<IndexModel> _logger;

        [BindProperty]
		public Register RModel { get; set; }

		public RegisterModel(ILogger<IndexModel> logger, UserManager<MemberIdentityUser> userManager,
		SignInManager<MemberIdentityUser> signInManager, IWebHostEnvironment environment)
		{
			_logger = logger;
			this.userManager = userManager;
			this.signInManager = signInManager;
            _environment = environment;
        }

		public void OnGet()
		{
            var password = HttpContext.Session.GetString("pwd");
			if (password == null)
			{
				password = "";
			}
            var strength = "";
			if (checkPassword(password) == 1) {
				strength = "Weak";
			}
            if (checkPassword(password) == 2)
            {
                strength = "Weak";
            }
            if (checkPassword(password) == 3)
            {
                strength = "Medium";
            }
            if (checkPassword(password) == 4)
            {
                strength = "Medium";
            }
            if (checkPassword(password) == 5)
            {
                strength = "Strong";
            }
            HttpContext.Session.SetString("pwdStrength", strength);
        }

		//Save data into the database
		public async Task<IActionResult> OnPostAsync()
		{

            if (ModelState.IsValid && checkPassword(RModel.Password) == 5)
			{
				if (checkInvalidChar())
				{
					ModelState.AddModelError("", "Invalid characters");
				}
				else
				{
                    // Add Image
                    var path = Path.Combine(_environment.WebRootPath, "uploads", RModel.Image.FileName);
                    using (FileStream stream = new FileStream(path, FileMode.Create))
                    {
                        await RModel.Image.CopyToAsync(stream);
                        stream.Close();
                    }

                    var dataProtectionProvider = DataProtectionProvider.Create("EncryptData");
					var protector = dataProtectionProvider.CreateProtector("SecretKey");

					// check if email already exists
					var user_emails = userManager.Users.ToList().Select(t=> t.Email);

					// guid for session
					var guid = Guid.NewGuid().ToString();

					if (!user_emails.Contains(RModel.EmailAddress))
					{

                        // TODO: NEED TO PROTECT USERNAME?
                        var user = new MemberIdentityUser()
						{
							UserName = RModel.EmailAddress,
							FirstName = encoder(protector.Protect(RModel.FirstName)),
							LastName = encoder(protector.Protect(RModel.LastName)),
							CreditCardNo = encoder(protector.Protect(RModel.CreditCardNo)),
							MobileNumber = encoder(protector.Protect(RModel.MobileNo)),
							BillingAddress = encoder(protector.Protect(RModel.BillingAddress)),
							ShippingAddress = encoder(protector.Protect(RModel.ShippingAddress)),
							ImagePath = protector.Protect(RModel.Image.FileName)
						};
						var result = await userManager.CreateAsync(user, RModel.Password);
						if (result.Succeeded)
						{
							await signInManager.SignInAsync(user, false);

                            // get logged in user
                            var loggedInUser = await userManager.FindByNameAsync(RModel.EmailAddress);
                            if (loggedInUser != null)
                            {
                                await userManager.UpdateSecurityStampAsync(loggedInUser);

                                // Add a cookie with same Guid value
                                CookieOptions options = new CookieOptions();
                                options.Secure = true;
                                options.HttpOnly = true;
                                Response.Cookies.Append("AuthCookie", loggedInUser.SecurityStamp, options);
                            }

                            return RedirectToPage("Index");
						}
						foreach (var error in result.Errors)
						{
							ModelState.AddModelError("", error.Description);
						}
					}
					ModelState.AddModelError("", "A user already has that email");
				}
			}
			return Page();
		}

        private byte[] encoder(string originalString)
        {
            byte[] encodedBytes = Encoding.ASCII.GetBytes(originalString);

            return encodedBytes;
        }

        private bool checkInvalidChar()
		{
			if (Regex.Matches(RModel.FirstName, @"[*&%#@$^!]").Count > 0)
			{
				return true;
			}
            if (Regex.Matches(RModel.LastName, @"[*&%#@$^!]").Count > 0)
            {
                return true;
            }
            if (Regex.Matches(RModel.CreditCardNo, @"[*&%#@$^!]").Count > 0)
            {
                return true;
            }
            if (Regex.Matches(RModel.MobileNo, @"[*&%#@$^!]").Count > 0)
            {
                return true;
            }
            if (Regex.Matches(RModel.BillingAddress, @"[*&%#@$^!]").Count > 0)
            {
                return true;
            }
            if (Regex.Matches(RModel.ShippingAddress, @"[*&%#@$^!]").Count > 0)
            {
                return true;
            }
            return false;
		}

		private int checkPassword(string password)
		{
			int score = 0;

			// Score 0
			if (password.Length < 8) return 1;
			else score = 1;

			// Score 2
			if (Regex.IsMatch(password, "[a-z]"))
			{
				score++;
			}

			// Score 3
			if (Regex.IsMatch(password, "[A-Z]"))
			{
				score++;
			}

			// Score 4
			if (Regex.IsMatch(password, "[0-9]"))
			{
				score++;
			}

			// Score 5
			if (Regex.IsMatch(password, "[`!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>\\/?~]"))
			{
				score++;
			}

			return score;
		}
	}
}
