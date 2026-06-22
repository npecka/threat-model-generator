# Application Load Balancer Configuration
# THREAT INJECTION: T01, T03, T18, T19, T21

# Application Load Balancer
resource "aws_lb" "quay" {
  name               = "quay-alb"
  internal           = false  # T01: Public-facing ALB
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = aws_subnet.public[*].id

  # T07: Access logs not enabled
  # access_logs {
  #   bucket  = aws_s3_bucket.alb_logs.id
  #   enabled = true
  # }

  # T03: No WAF attached
  # enable_waf = true

  # T19: No connection draining for graceful shutdown
  enable_deletion_protection = false

  tags = {
    Name = "quay-alb"
  }
}

# Target Group for Quay Application
resource "aws_lb_target_group" "quay_app" {
  name     = "quay-app-tg"
  port     = 8080
  protocol = "HTTP"  # T03: HTTP instead of HTTPS
  vpc_id   = aws_vpc.quay_vpc.id

  health_check {
    enabled             = true
    healthy_threshold   = 2
    unhealthy_threshold = 3
    timeout             = 5
    interval            = 30
    path                = "/health/instance"
    matcher             = "200"
  }

  # T21: Health check interval too long for HA
  # T18: No proper session affinity could cause split-brain
  stickiness {
    enabled = false  # T20: No session stickiness
    type    = "lb_cookie"
  }

  # T19: Immediate deregistration, no drain
  deregistration_delay = 0

  tags = {
    Name = "quay-app-tg"
  }
}

# HTTP Listener (T03: No HTTPS)
resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.quay.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.quay_app.arn
  }

  # T03: Should redirect to HTTPS
  # default_action {
  #   type = "redirect"
  #   redirect {
  #     port        = "443"
  #     protocol    = "HTTPS"
  #     status_code = "HTTP_301"
  #   }
  # }
}

# HTTPS Listener (Commented out - T03)
# resource "aws_lb_listener" "https" {
#   load_balancer_arn = aws_lb.quay.arn
#   port              = "443"
#   protocol          = "HTTPS"
#   ssl_policy        = "ELBSecurityPolicy-TLS-1-2-2017-01"
#   certificate_arn   = aws_acm_certificate.quay.arn
#
#   default_action {
#     type             = "forward"
#     target_group_arn = aws_lb_target_group.quay_app.arn
#   }
# }

# Target Group for LLM Service
resource "aws_lb_target_group" "llm_service" {
  name     = "llm-service-tg"
  port     = 8000
  protocol = "HTTP"
  vpc_id   = aws_vpc.quay_vpc.id

  health_check {
    enabled             = true
    healthy_threshold   = 2
    unhealthy_threshold = 3
    timeout             = 10
    interval            = 60  # T21: Long interval for slow model loading
    path                = "/health"
    matcher             = "200"
  }

  # T20: No consistency checks for model versions across instances
  stickiness {
    enabled = false
  }

  deregistration_delay = 0

  tags = {
    Name = "llm-service-tg"
  }
}

# LLM Service Listener Rule
resource "aws_lb_listener_rule" "llm_service" {
  listener_arn = aws_lb_listener.http.arn
  priority     = 100

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.llm_service.arn
  }

  condition {
    path_pattern {
      values = ["/llm/*"]
    }
  }
}

# Target Group for Clair Scanner
resource "aws_lb_target_group" "clair" {
  name     = "clair-tg"
  port     = 6060
  protocol = "HTTP"
  vpc_id   = aws_vpc.quay_vpc.id

  health_check {
    enabled             = true
    healthy_threshold   = 2
    unhealthy_threshold = 3
    timeout             = 5
    interval            = 30
    path                = "/health"
    matcher             = "200"
  }

  stickiness {
    enabled = false
  }

  deregistration_delay = 0

  tags = {
    Name = "clair-tg"
  }
}

# Clair Listener Rule
resource "aws_lb_listener_rule" "clair" {
  listener_arn = aws_lb_listener.http.arn
  priority     = 200

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.clair.arn
  }

  condition {
    path_pattern {
      values = ["/clair/*"]
    }
  }
}

# Network Load Balancer for Redis (Internal - HA)
# T18-T21: NLB doesn't prevent split-brain or ensure consistency
resource "aws_lb" "redis" {
  name               = "quay-redis-nlb"
  internal           = true  # Internal only
  load_balancer_type = "network"
  subnets            = aws_subnet.private[*].id

  enable_deletion_protection = false

  tags = {
    Name = "quay-redis-nlb"
  }
}

# Redis Target Group
resource "aws_lb_target_group" "redis" {
  name     = "redis-tg"
  port     = 6379
  protocol = "TCP"
  vpc_id   = aws_vpc.quay_vpc.id

  health_check {
    enabled             = true
    healthy_threshold   = 2
    unhealthy_threshold = 2
    timeout             = 5
    interval            = 10
    protocol            = "TCP"
  }

  # T21: Fast failover but no coordination
  deregistration_delay = 0

  tags = {
    Name = "redis-tg"
  }
}

resource "aws_lb_listener" "redis" {
  load_balancer_arn = aws_lb.redis.arn
  port              = "6379"
  protocol          = "TCP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.redis.arn
  }
}

# Outputs
output "alb_dns_name" {
  value       = aws_lb.quay.dns_name
  description = "DNS name of the Application Load Balancer"
}

output "alb_zone_id" {
  value       = aws_lb.quay.zone_id
  description = "Zone ID of the Application Load Balancer"
}
