# Terraform Variables for Minimal Single-AZ Deployment
# Auto-configured for testing

aws_region  = "us-east-1"
environment = "threat-modeling"

# VPC Configuration
vpc_cidr = "10.0.0.0/16"

# Database Configuration
db_password = "insecure_password_123"  # T08: Weak password for demonstration

# SSH Access
ssh_public_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC/yuPiGJrR3hST0My9hKOQXpmAP7WKLegJ8F3jVvsQnpiq8h+ITSpGDt0K4a3WtGyxB38r4dTpyhRtm+OfCcz8Ib9je0sfQOCMp/m12WAo+4xRR3zTzKmvqcsSOdfJROohaFIlkvEnVl+PCf60F0amYiV1AccjTldnRL1Q7L5rgwVmvgVymc67Ml5YRyWxTU0hblAj0i7M7uSZyqEmBWYzTmcDmhrB+H2Smc8uqq99/KrWDJ4+VqupTatzPWxK2rxE1CLJHniZhG+Kb+I2yVZ59ogDidX0tOa4znVXERuqJoF4Nau2aS/gXknUFaWZTW0fdCm1pjn3MbV+n/p9hPxUTzS8C8IM6pgRS26O8khuyJszc2zltZJpM+vDiafVst0XtdS8x9s6HBf0X2DVvdVUSJy/4gRRzkQDyb/PfHBlJYc/aMlvPffWJhwJNcQGr+df0A4UnGXpkdYxgh8y/Bzb5hSfbN5o5JFSsYsJamGFPh99VUvRyMHty2R3je3ZJTQ3MQv6nzu4wKtp8tn0u2WvdSR4rBQpl00xOh9mqny/Pf50T6peBrzmCEUfZ5BD2f26i/TG7C4e8C5SNiBWHSzxvEf03qfM/PQLBShmVKZ9vr9sZXgM4RJj5DWpKxqfb8LCQLZ1xQTk9D89rGvwzv/CCcfXuvXPKyJg/OcPfMweIQ== quay-minimal-deployment"

# Tagging
project_name = "threat-model-generator"
case_study   = "quay-minimal"
owner        = "nicholas.pecka"
