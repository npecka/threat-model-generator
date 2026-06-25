# IAM Users for Console Access
# THREAT INJECTION: T09 (Weak Authentication - No MFA)

# T09: IAM user for Quay admin console access without MFA
resource "aws_iam_user" "quay_admin" {
  name = "quay-admin-console"

  tags = {
    Name        = "quay-admin-console"
    Description = "Admin user for Quay console access"
  }
}

# T09: Console access enabled but MFA not enforced
resource "aws_iam_user_login_profile" "quay_admin_login" {
  user                    = aws_iam_user.quay_admin.name
  password_reset_required = false
}

# T09: Administrative access without MFA requirement
resource "aws_iam_user_policy_attachment" "quay_admin_policy" {
  user       = aws_iam_user.quay_admin.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# Output to show T09 threat exists
output "iam_user_warnings" {
  description = "Security warnings about IAM users"
  value = {
    user_name    = aws_iam_user.quay_admin.name
    threat       = "T09: User has console access without MFA"
    severity     = "HIGH"
    recommendation = "Enable MFA for ${aws_iam_user.quay_admin.name}"
  }
}
